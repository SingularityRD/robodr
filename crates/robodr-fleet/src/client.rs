//! The SOC client: robodr-uplink's HTTPS transport
//! (`robodr_export::uplink::http`: rustls + ring, the operator's CA bundle
//! as the only trust anchor, optional SPKI pins, no verification bypass,
//! plain HTTP only to a loopback IP literal, bounded timeouts and response
//! sizes) with the fleet API's paths and request authentication (contract
//! §2.5).

use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::Ed25519SigningKey;
use robodr_export::uplink::http::{self, Endpoint, HttpRequest, HttpsTransport, Timeouts};
use std::path::Path;

use crate::wire;

pub use robodr_export::uplink::http::{HttpResponse, TransportError};

/// One HTTP exchange with the SOC. [`Https`] is the real one; tests
/// substitute an in-memory SOC.
pub trait SocTransport {
    /// `target` is the fleet path (e.g. [`wire::PATH_RING`]); the transport
    /// prefixes the API root's base path.
    fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: Vec<(&'static str, String)>,
        body: &[u8],
    ) -> Result<HttpResponse, TransportError>;

    /// The base path the request target is prefixed with (`/api` behind
    /// the stock Caddy front end); part of the signed request message.
    fn base_path(&self) -> String;
}

/// HTTPS to the SOC's API root.
pub struct Https {
    inner: HttpsTransport,
    base: String,
}

impl Https {
    /// `url` is the API root (`https://soc.example.org/api`); `ca_bundle` the
    /// PEM trust anchors; `pins` optional SHA-256 SPKI pins (64 hex).
    pub fn new(url: &str, ca_bundle: Option<&Path>, pins: &[String]) -> Result<Self, String> {
        let ep = Endpoint::parse_with_path(url, "")?;
        let pins = pins
            .iter()
            .map(|p| http::parse_pin(p))
            .collect::<Result<Vec<_>, _>>()?;
        let tls = if ep.tls {
            let ca = ca_bundle.ok_or("an https:// SOC URL needs a CA bundle (--ca-bundle)")?;
            Some(http::client_config(http::load_ca_bundle(ca)?, &pins)?)
        } else {
            None
        };
        let base = ep.path.clone();
        let mut inner = HttpsTransport::new(ep, tls, Timeouts::default())?;
        inner.set_user_agent(&format!("robodr-enroll/{}", env!("CARGO_PKG_VERSION")))?;
        Ok(Self { inner, base })
    }
}

impl SocTransport for Https {
    fn send(
        &mut self,
        method: &str,
        target: &str,
        headers: Vec<(&'static str, String)>,
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let full = format!("{}{target}", self.base);
        self.inner
            .request(method, &full, &HttpRequest { headers, body })
    }

    fn base_path(&self) -> String {
        self.base.clone()
    }
}

/// The request-authentication headers (§2.5) for `method` + `target` (the
/// full origin-form target, base path included) + `body`, signed by `key`
/// at `now_ms`.
pub fn auth_headers(
    method: &str,
    full_target: &str,
    body: &[u8],
    key: &Ed25519SigningKey,
    now_ms: u64,
) -> Vec<(&'static str, String)> {
    let key_id = robodr_blackbox::Signer::key_id(key).to_string();
    let sig = key.sign_message(&wire::request_message(
        method,
        full_target,
        &key_id,
        now_ms,
        body,
    ));
    vec![
        ("X-RoboDR-Key-Id", key_id),
        ("X-RoboDR-Timestamp", now_ms.to_string()),
        ("X-RoboDR-Signature", to_hex(&sig)),
    ]
}

/// A failed exchange, classified for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocError {
    /// No response (connect, TLS, timeout): retry later.
    Transport(String),
    /// The SOC refused: status, code, detail.
    Refused {
        status: u16,
        code: String,
        detail: String,
    },
}

impl std::fmt::Display for SocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "SOC not reached: {e}"),
            Self::Refused {
                status,
                code,
                detail,
            } => write!(f, "SOC refused ({status} {code}): {detail}"),
        }
    }
}

/// Send and require `200`; any other status is [`SocError::Refused`] with
/// the error body's code (`"unknown"` when it has none).
pub fn exchange(
    t: &mut dyn SocTransport,
    method: &str,
    target: &str,
    body: &[u8],
    auth: Option<(&Ed25519SigningKey, u64)>,
) -> Result<Vec<u8>, SocError> {
    let mut headers: Vec<(&'static str, String)> = Vec::new();
    if !body.is_empty() || method == "POST" {
        headers.push(("Content-Type", "application/json".into()));
    }
    if let Some((k, now)) = auth {
        let full = format!("{}{target}", t.base_path());
        headers.extend(auth_headers(method, &full, body, k, now));
    }
    let r = t
        .send(method, target, headers, body)
        .map_err(|e| SocError::Transport(e.to_string()))?;
    if r.status == 200 {
        return Ok(r.body);
    }
    let (code, detail) =
        wire::error_code(&r.body).unwrap_or_else(|| ("unknown".into(), String::new()));
    Err(SocError::Refused {
        status: r.status,
        code,
        detail,
    })
}
