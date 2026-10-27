//! Update-ring information (contract §7; SECURE-DELIVERY 13a scope): the
//! SOC tells the unit which staged-rollout ring it is in (0 canary, 1
//! early, 2 broad) and which release that ring targets. **Information
//! only**: nothing here downloads or installs anything. Installing stays a
//! local, operator-approved step (`install-bundle.sh install`, with its
//! signature check), never triggered remotely.
//!
//! Anti-rollback: a ring document with a lower `serial` than the last
//! accepted one is refused, the same serial must be the same document, and
//! a document issued in the future (beyond the clock skew) is refused.
//!
//! The one thing ring information can change on the unit is a restriction:
//! its `min_version` raises the unit's security floor, below which
//! `install-bundle.sh` installs and rolls back nothing (it reads
//! `ring.env`). It never makes anything install.

use crate::client::{self, SocTransport};
use crate::keys::{self, SocKeys};
use crate::state::{Ctx, RingMark};
use crate::wire::{self, Envelope, RingInfo};

const RING: &str = "ring.json";

/// What the unit should show the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingStatus {
    pub info: RingInfo,
    /// The installed release (dpkg's record of the package, upstream form;
    /// this binary's version when dpkg knows none).
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
    if info.issued_at_ms > ctx.now().saturating_add(wire::MAX_SKEW_MS) {
        return Err(format!(
            "ring info is issued in the future ({} ms; unit clock {} ms): fix the unit's clock",
            info.issued_at_ms,
            ctx.now()
        ));
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
    write_env(ctx, &info)?;
    let installed = installed_release();
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
        "min_version": status.info.min_version,
        "bundle_sha256": status.info.bundle_sha256,
        "installed_version": status.installed_version,
        "stale": status.stale,
    }))?;
    j.close()?;
    Ok(status)
}

/// `ring.env`: the verified ring information as plain `key=value` lines for
/// `install-bundle.sh` (which prints it and never sources it). Every value
/// has passed [`RingInfo::parse`] (restricted character sets).
fn write_env(ctx: &Ctx, info: &RingInfo) -> Result<(), String> {
    let text = format!(
        "# robodr-enroll: SOC update-ring information (verified). Information only,\n\
         # except min_version: install-bundle.sh raises the security floor to it.\n\
         serial={}\nring={}\ntarget_version={}\nmin_version={}\nbundle_sha256={}\nexpires_at_ms={}\nstale={}\n",
        info.serial,
        info.ring,
        info.target_version.as_deref().unwrap_or(""),
        info.min_version.as_deref().unwrap_or(""),
        info.bundle_sha256.as_deref().unwrap_or(""),
        info.expires_at_ms,
        ctx.now() > info.expires_at_ms
    );
    let p = ctx.path("ring.env");
    crate::fsx::write_atomic(&p, text.as_bytes()).map_err(|e| format!("{}: {e}", p.display()))
}

/// The installed RoboDR release, upstream form: dpkg's record of the
/// `robodr` or `robodr-focal` package (what `install-bundle.sh` installed),
/// else this binary's own version.
pub fn installed_release() -> String {
    let q = if std::path::Path::new("/usr/bin/dpkg-query").exists() {
        "/usr/bin/dpkg-query"
    } else {
        "dpkg-query"
    };
    for p in ["robodr", "robodr-focal"] {
        let Ok(o) = std::process::Command::new(q)
            .args(["-W", "-f", "${db:Status-Abbrev} ${Version}", p])
            .stderr(std::process::Stdio::null())
            .output()
        else {
            break;
        };
        let t = String::from_utf8_lossy(&o.stdout);
        if o.status.success() && t.starts_with("ii") {
            if let Some(u) = t.split_whitespace().last().and_then(upstream_of) {
                return u;
            }
        }
    }
    env!("CARGO_PKG_VERSION").to_string()
}

/// The upstream release of a Debian version (`[epoch:]upstream[-revision]`;
/// a pre-release `~` back to `-`, as `build-deb.sh` maps it).
pub fn upstream_of(deb: &str) -> Option<String> {
    let v = deb.split_once(':').map_or(deb, |(_, r)| r);
    let v = v.rsplit_once('-').map_or(v, |(u, _)| u);
    let u = v.replacen('~', "-", 1);
    wire::is_version(&u).then_some(u)
}

#[cfg(test)]
mod tests {
    use super::upstream_of;

    #[test]
    fn upstream_of_debian_versions() {
        assert_eq!(
            upstream_of("0.1.0~alpha.1-1").as_deref(),
            Some("0.1.0-alpha.1")
        );
        assert_eq!(upstream_of("0.2.0-1").as_deref(), Some("0.2.0"));
        assert_eq!(upstream_of("1:0.2.0-3").as_deref(), Some("0.2.0"));
        assert_eq!(upstream_of("0.2.0").as_deref(), Some("0.2.0"));
        assert_eq!(upstream_of("x").as_deref(), None);
    }
}
