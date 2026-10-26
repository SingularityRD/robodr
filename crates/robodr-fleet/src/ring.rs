//! Update-ring information (contract §7; SECURE-DELIVERY 13a scope): the
//! SOC tells the unit which staged-rollout ring it is in (0 canary, 1
//! early, 2 broad) and which release that ring targets. **Information
//! only**: nothing here downloads or installs anything. Installing stays a
//! local, operator-approved step (`install-bundle.sh install`, with its
//! signature check), never triggered remotely.
//!
//! Anti-rollback: a ring document with a lower `serial` than the last
//! accepted one is refused, the same serial must be the same document.

use crate::client::{self, SocTransport};
use crate::keys::{self, SocKeys};
use crate::state::{Ctx, RingMark};
use crate::wire::{self, Envelope, RingInfo};

const RING: &str = "ring.json";

/// What the unit should show the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingStatus {
    pub info: RingInfo,
    pub installed_version: String,
    /// `target_version` differs from the installed version.
    pub update_available: bool,
    /// The document's `expires_at_ms` has passed (withheld updates are
    /// visible: SECURE-DELIVERY §6.5).
    pub stale: bool,
}

/// Fetch and [`accept`] the ring document.
pub fn fetch(ctx: &Ctx, t: &mut dyn SocTransport) -> Result<RingStatus, String> {
    ctx.enrollment()?;
    let auth = keys::load("uplink", &ctx.cfg.uplink_key)?;
    let body = client::exchange(
        t,
        "GET",
        wire::PATH_RING,
        b"",
        Some((&auth.signing, ctx.now())),
    )
    .map_err(|e| e.to_string())?;
    accept(ctx, &body)
}

/// Verify a ring document (SOC signature, this robot, serial) and record it.
pub fn accept(ctx: &Ctx, bytes: &[u8]) -> Result<RingStatus, String> {
    let en = ctx.enrollment()?;
    let o = Envelope::parse(bytes, wire::T_RING).map_err(|e| format!("ring info: {e}"))?;
    SocKeys::load(&ctx.cfg.soc_keys)?
        .verify(&o)
        .map_err(|e| format!("ring info: {e}"))?;
    let info = RingInfo::parse(&o.payload).map_err(|e| format!("ring info: {e}"))?;
    if info.workspace != en.workspace || info.robot_id != en.robot_id {
        return Err("ring info is for another robot or workspace".into());
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| "not UTF-8")?;
    if let Some(m) = ctx.load::<RingMark>(RING)? {
        if info.serial < m.serial {
            return Err(format!(
                "ring info rollback refused: serial {} < last accepted {}",
                info.serial, m.serial
            ));
        }
        if info.serial == m.serial {
            let prev =
                Envelope::parse(m.envelope.as_bytes(), wire::T_RING).map_err(|e| e.to_string())?;
            if prev.payload != o.payload {
                return Err(format!(
                    "ring info equivocation refused: serial {} with other content",
                    info.serial
                ));
            }
        }
    }
    ctx.store(
        RING,
        &RingMark {
            serial: info.serial,
            envelope: text,
        },
    )?;
    let installed = env!("CARGO_PKG_VERSION").to_string();
    let status = RingStatus {
        update_available: info
            .target_version
            .as_deref()
            .is_some_and(|v| v != installed),
        stale: ctx.now() > info.expires_at_ms,
        installed_version: installed,
        info,
    };
    let mut j = ctx.journal(&en.robot_id)?;
    j.note(&serde_json::json!({
        "kind": crate::journal::K_RING,
        "serial": status.info.serial,
        "ring": status.info.ring,
        "target_version": status.info.target_version,
        "bundle_sha256": status.info.bundle_sha256,
        "installed_version": status.installed_version,
        "stale": status.stale,
    }))?;
    j.close()?;
    Ok(status)
}
