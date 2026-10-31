//! `robodr-demo-soc --config soc.json [--listen 127.0.0.1:8080] [--store findings.ndjson]`
//!
//! See the crate docs (`src/lib.rs`). Exit 2 on usage or configuration
//! errors.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use robodr_demo_soc::http::{read_request, write_response, Bad, Request};
use robodr_demo_soc::ingest::Consumer;
use robodr_demo_soc::store::Store;
use robodr_demo_soc::{config, viewer};
use serde_json::json;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

const USAGE: &str =
    "usage: robodr-demo-soc --config soc.json [--listen 127.0.0.1:8080] [--store findings.ndjson]";
/// Concurrent connections served; more are answered 503.
const MAX_CONNECTIONS: usize = 32;

struct State {
    consumer: Consumer,
    store: Store,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn query_limit(path: &str) -> usize {
    path.split_once('?')
        .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("limit=")))
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(robodr_demo_soc::store::MEMORY)
}

fn handle(
    req: &Request,
    state: &Mutex<State>,
) -> (u16, &'static str, Vec<(&'static str, String)>, Vec<u8>) {
    let route = req.path.split('?').next().unwrap_or("");
    let json_ct = "application/json";
    match (req.method.as_str(), route) {
        ("POST", "/robot-edr/v2/ingest") => {
            let now = unix_ms();
            let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
            st.consumer.now_ms = Some(now);
            let a = st.consumer.handle(&req.headers, &req.body);
            // The reference consumer records every request; the demo keeps
            // only its own store.
            st.consumer.seen.clear();
            if a.status == 200 {
                let answer: serde_json::Value = serde_json::from_slice(&a.body).unwrap_or_default();
                if answer.get("replayed") != Some(&serde_json::Value::Bool(true)) {
                    let n = st.store.ingest(&req.body, &answer, now);
                    eprintln!(
                        "robodr-demo-soc: batch accepted: {n} new finding(s), {} rejected line(s)",
                        answer
                            .get("rejected")
                            .and_then(serde_json::Value::as_array)
                            .map_or(0, Vec::len)
                    );
                }
            } else {
                eprintln!(
                    "robodr-demo-soc: batch refused: {} {}",
                    a.status,
                    String::from_utf8_lossy(&a.body)
                );
            }
            let extra = a
                .retry_after
                .map(|r| vec![("Retry-After", r)])
                .unwrap_or_default();
            (a.status, json_ct, extra, a.body)
        }
        ("GET", "/") => (
            200,
            "text/html; charset=utf-8",
            vec![],
            viewer::INDEX_HTML.into(),
        ),
        ("GET", "/app.js") => (
            200,
            "text/javascript; charset=utf-8",
            vec![],
            viewer::APP_JS.into(),
        ),
        ("GET", "/app.css") => (
            200,
            "text/css; charset=utf-8",
            vec![],
            viewer::APP_CSS.into(),
        ),
        ("GET", "/api/findings") => {
            let st = state.lock().unwrap_or_else(PoisonError::into_inner);
            let v = st.store.recent(query_limit(&req.path));
            (
                200,
                json_ct,
                vec![],
                serde_json::to_vec(&v).unwrap_or_default(),
            )
        }
        ("GET", "/api/metrics") => {
            let st = state.lock().unwrap_or_else(PoisonError::into_inner);
            (
                200,
                json_ct,
                vec![],
                st.store.metrics().to_string().into_bytes(),
            )
        }
        ("GET", "/healthz") => (200, json_ct, vec![], br#"{"ok":true}"#.to_vec()),
        (_, "/robot-edr/v2/ingest" | "/" | "/api/findings" | "/api/metrics") => (
            405,
            json_ct,
            vec![],
            br#"{"code":"method_not_allowed"}"#.to_vec(),
        ),
        _ => (404, json_ct, vec![], br#"{"code":"not_found"}"#.to_vec()),
    }
}

fn serve(mut conn: TcpStream, state: &Mutex<State>) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
    let (status, ct, extra, body) = match read_request(&mut conn) {
        Ok(req) => handle(&req, state),
        Err(Bad(s, why)) => (
            s,
            "application/json",
            vec![],
            json!({"code": "bad_request", "detail": why})
                .to_string()
                .into_bytes(),
        ),
    };
    let _ = write_response(&mut conn, status, ct, &extra, &body);
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut cfg = None;
    let mut listen = "127.0.0.1:8080".to_string();
    let mut store_file = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => cfg = args.next().map(PathBuf::from),
            "--listen" => listen = args.next().unwrap_or_default(),
            "--store" => store_file = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unknown argument {other:?}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(cfg) = cfg else {
        eprintln!("error: --config is required\n{USAGE}");
        return ExitCode::from(2);
    };
    let reg = match config::load(&cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: listen {listen}: {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "robodr-demo-soc: {} robot(s), {} key(s); listening on http://{listen}/",
        reg.robots.len(),
        reg.keys.len()
    );
    let state = Arc::new(Mutex::new(State {
        consumer: Consumer::new(reg),
        store: Store::new(store_file),
    }));
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let mut conn = conn;
            let _ = write_response(
                &mut conn,
                503,
                "application/json",
                &[("Retry-After", "1".into())],
                b"{}",
            );
            continue;
        }
        let (state, active) = (Arc::clone(&state), Arc::clone(&active));
        std::thread::spawn(move || {
            serve(conn, &state);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    ExitCode::SUCCESS
}
