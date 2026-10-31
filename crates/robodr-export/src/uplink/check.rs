//! `robodr-uplink --check`: the site-acceptance connectivity check of the
//! uplink path, **without sending a finding**.
//!
//! 1. TLS: the transport connects with the configured CA bundle, SPKI pins
//!    and CRLs (a revoked or unknown server is "not reached").
//! 2. Ingest endpoint: a request with valid `X-RoboDR-*` headers and an
//!    **empty body** to `{url}/robot-edr/v2/ingest`. The ingest contract
//!    (§4 step 1.3) refuses it with `400 empty_batch` before any key lookup
//!    and before anything is stored: that answer proves the URL reaches a
//!    RoboDR ingest API, and nothing else does.
//! 3. Key: an `uplink` key is also the robot's fleet request key
//!    (`robodr.fleet-api` §2.5), so a read-only, authenticated
//!    `GET {url}/robot-edr/v2/fleet/ring` proves the SOC knows the key and
//!    the clocks agree (`200` or `404 no_ring`; `401` names the reason). A
//!    `relay` key (diode importer, `--diode-out`) authenticates at ingest
//!    only, so this step is skipped for it and its registration is
//!    confirmed by the first delivered batch; likewise when the SOC does
//!    not serve the fleet API (`404 not_found`).
//!
//! Nothing is written to the state directory, no lock is taken (it runs
//! next to the service), and no batch id is consumed (the probe's random
//! id is refused before the server's replay store).

use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::sign_ed25519::Ed25519SigningKey;

use super::http::{HttpRequest, HttpResponse, HttpsTransport, TransportError};
use super::wire;

/// The fleet ring path below the API root (`robodr.fleet-api` §1).
pub const FLEET_RING_PATH: &str = "/robot-edr/v2/fleet/ring";
/// Request-authentication domain of `robodr.fleet-api` §2.5.
pub const FLEET_REQUEST_DOMAIN: &[u8] = b"robodr-fleet/request/v1\0";

/// How the check ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed(String),
}

/// One line per step, then the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub lines: Vec<String>,
    pub outcome: Outcome,
}

/// One request; [`HttpsTransport`] in production, a fake in tests.
pub trait Probe {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        req: &HttpRequest<'_>,
    ) -> Result<HttpResponse, TransportError>;
    /// The ingest request target (base path + ingest path).
    fn ingest_target(&self) -> String;
}

impl Probe for HttpsTransport {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        req: &HttpRequest<'_>,
    ) -> Result<HttpResponse, TransportError> {
        self.request(method, target, req)
    }
    fn ingest_target(&self) -> String {
        self.endpoint().path.clone()
    }
}

fn framed(m: &mut Vec<u8>, part: &[u8]) {
    m.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
    m.extend_from_slice(part);
}

/// The `robodr.fleet-api` §2.5 request message (kept identical to
/// `robodr_fleet::wire::request_message`; a robodr-fleet test compares
/// them).
pub fn fleet_request_message(
    method: &str,
    target: &str,
    key_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut m = FLEET_REQUEST_DOMAIN.to_vec();
    framed(&mut m, method.as_bytes());
    framed(&mut m, target.as_bytes());
    framed(&mut m, key_id.as_bytes());
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m.extend_from_slice(&sha256(body));
    m
}

fn code(r: &HttpResponse) -> String {
    #[derive(serde::Deserialize)]
    struct E {
        code: String,
    }
    serde_json::from_slice::<E>(&r.body)
        .ok()
        .map(|e| e.code)
        .filter(|c| wire::is_valid_code(c))
        .unwrap_or_else(|| "unknown".into())
}

fn done(lines: Vec<String>, outcome: Outcome) -> Report {
    Report { lines, outcome }
}

/// Run the check. `relay`: the key is a relay key (`--diode-out`), whose
/// registration cannot be checked without a batch. `batch_nonce`: 16
/// random bytes for the probe's batch id.
pub fn run(
    t: &mut dyn Probe,
    key: &Ed25519SigningKey,
    relay: bool,
    now_ms: u64,
    batch_nonce: [u8; 16],
) -> Report {
    let mut lines = Vec::new();
    let key_id = robodr_blackbox::Signer::key_id(key).to_string();
    lines.push(format!("ok   sender key {key_id} loaded"));
    // Step 2: empty-body probe (also step 1: TLS).
    let ingest = t.ingest_target();
    let batch_id = format!("{}{}", wire::BATCH_ID_PREFIX, to_hex(&batch_nonce));
    let headers = vec![
        ("Content-Type", wire::CONTENT_TYPE.to_string()),
        (wire::H_KEY_ID, key_id.clone()),
        (wire::H_BATCH_ID, batch_id.clone()),
        (wire::H_TIMESTAMP, now_ms.to_string()),
        (
            wire::H_SIGNATURE,
            wire::sign_batch(key, &key_id, &batch_id, now_ms, b""),
        ),
    ];
    match t.send("POST", &ingest, &HttpRequest { headers, body: b"" }) {
        Err(e) => {
            return done(
                lines,
                Outcome::Failed(format!(
                    "the SOC was not reached (connect, TLS, pin or CRL): {e}"
                )),
            )
        }
        Ok(r) if r.status == 400 && code(&r) == "empty_batch" => {
            lines.push("ok   TLS to the SOC (CA bundle, pins, CRLs)".into());
            lines.push(format!(
                "ok   {ingest} is the RoboDR ingest API (an empty batch is refused: \
                 400 empty_batch; nothing was sent)"
            ));
        }
        Ok(r) => {
            lines.push("ok   TLS to the SOC (CA bundle, pins, CRLs)".into());
            return done(
                lines,
                Outcome::Failed(format!(
                    "{ingest} answered {} {} to an empty batch instead of 400 empty_batch: \
                     not the RoboDR ingest API (check --url: the API root, e.g. \
                     https://soc.example.org/api)",
                    r.status,
                    code(&r)
                )),
            );
        }
    }
    if relay {
        lines.push(
            "skip key registration: a relay key (--diode-out) authenticates at ingest only; \
             the first delivered batch confirms it"
                .into(),
        );
        return done(lines, Outcome::Ok);
    }
    // Step 3: the key, through the fleet API (read-only).
    let base = ingest
        .strip_suffix(wire::INGEST_PATH)
        .unwrap_or_default()
        .to_string();
    let target = format!("{base}{FLEET_RING_PATH}");
    let sig = key.sign_message(&fleet_request_message("GET", &target, &key_id, now_ms, b""));
    let headers = vec![
        ("X-RoboDR-Key-Id", key_id.clone()),
        ("X-RoboDR-Timestamp", now_ms.to_string()),
        ("X-RoboDR-Signature", to_hex(&sig)),
    ];
    match t.send("GET", &target, &HttpRequest { headers, body: b"" }) {
        Err(e) => done(
            lines,
            Outcome::Failed(format!("the SOC was not reached: {e}")),
        ),
        Ok(r) if r.status == 200 => {
            lines.push(format!(
                "ok   the SOC accepts key {key_id} (fleet request auth)"
            ));
            done(lines, Outcome::Ok)
        }
        Ok(r) if r.status == 404 && code(&r) == "no_ring" => {
            lines.push(format!(
                "ok   the SOC accepts key {key_id} (fleet request auth)"
            ));
            done(lines, Outcome::Ok)
        }
        Ok(r) if r.status == 404 => {
            lines.push(
                "warn key registration not checked: the SOC does not serve the fleet API; \
                 the first delivered batch confirms the key"
                    .into(),
            );
            done(lines, Outcome::Ok)
        }
        Ok(r) => {
            let c = code(&r);
            let hint = match c.as_str() {
                "unknown_key" => {
                    "the key is not registered as an active uplink key (enrolled? retired?)"
                }
                "stale_timestamp" => "the unit clock is more than 300 s off the SOC's",
                "bad_signature" => "the SOC registered another public key under this key id",
                _ => "see the SOC's audit log",
            };
            done(
                lines,
                Outcome::Failed(format!(
                    "the SOC refused key {key_id}: {} {c} ({hint})",
                    r.status
                )),
            )
        }
    }
}
