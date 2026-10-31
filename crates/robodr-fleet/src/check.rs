//! `robodr-enroll check`: the site-acceptance connectivity check of the
//! fleet path. It proves, without changing anything on the unit or at the
//! SOC, that:
//!
//! 1. the SOC fleet public keys (and approval keys, if configured) load
//!    under the file rules of contract §2.7;
//! 2. the SOC answers over TLS with the configured CA bundle, SPKI pins and
//!    CRLs (the transport refuses anything else; a failure here is "not
//!    reached");
//! 3. the URL reaches the fleet API (not some other service behind the
//!    same front end);
//! 4. on an enrolled unit: the active uplink key file is the registered
//!    one, and the SOC accepts a request authenticated by it (§2.5:
//!    `GET …/ring`, read-only); a ring document, if one is published, is
//!    verified against the configured SOC fleet keys (but not recorded).
//!
//! Nothing is written: no state file, no journal note, no ring record.

use crate::client::{self, SocError, SocTransport};
use crate::keys::{self, SocKeys};
use crate::state::Ctx;
use crate::wire::{self, Envelope};

/// How the check ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every step passed.
    Ok,
    /// A step failed (configuration, keys, authentication).
    Refused(String),
    /// The SOC was not reached (network, TLS, CRL).
    Unreachable(String),
}

/// The report: one line per step, then the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub lines: Vec<String>,
    pub outcome: Outcome,
}

fn done(lines: Vec<String>, outcome: Outcome) -> Report {
    Report { lines, outcome }
}

/// Run the check against `t` (the configured SOC).
pub fn run(ctx: &Ctx, t: &mut dyn SocTransport) -> Report {
    let mut lines = Vec::new();
    let soc = match SocKeys::load(&ctx.cfg.soc_keys) {
        Ok(k) => {
            lines.push(format!(
                "ok   SOC fleet keys: {} file(s) loaded",
                ctx.cfg.soc_keys.len()
            ));
            k
        }
        Err(e) => return done(lines, Outcome::Refused(format!("SOC fleet keys: {e}"))),
    };
    if !ctx.cfg.approval_keys.is_empty() {
        match SocKeys::load_approval(&ctx.cfg.approval_keys, &ctx.cfg.soc_keys) {
            Ok(_) => lines.push(format!(
                "ok   SOC approval keys: {} file(s) loaded, distinct from the fleet keys",
                ctx.cfg.approval_keys.len()
            )),
            Err(e) => return done(lines, Outcome::Refused(format!("SOC approval keys: {e}"))),
        }
    }
    let enrollment = match ctx.load::<crate::state::Enrollment>("enrollment.json") {
        Ok(e) => e,
        Err(e) => return done(lines, Outcome::Refused(e)),
    };
    let Some(en) = enrollment else {
        // Not enrolled: an unauthenticated request must reach the fleet
        // API and be refused there for its missing headers (§2.5).
        return match client::exchange(t, "GET", wire::PATH_RING, &[], None) {
            Err(SocError::Refused {
                status: 400, code, ..
            }) if code == "bad_header" => {
                lines.push(
                    "ok   TLS to the SOC (CA bundle, pins, CRLs) and the fleet API answers".into(),
                );
                lines.push("skip request authentication: this unit is not enrolled yet".into());
                done(lines, Outcome::Ok)
            }
            Err(SocError::Transport(e)) => {
                done(lines, Outcome::Unreachable(format!("SOC not reached: {e}")))
            }
            Err(e @ SocError::Refused { .. }) => done(
                lines,
                Outcome::Refused(format!(
                    "the URL does not answer as the fleet API ({e}); check soc.url (the API \
                     root, e.g. https://soc.example.org/api)"
                )),
            ),
            Ok(_) => done(
                lines,
                Outcome::Refused(
                    "the SOC answered an unauthenticated request with 200; refusing to trust \
                     it as the fleet API"
                        .into(),
                ),
            ),
        };
    };
    let auth = match keys::load("uplink", &ctx.cfg.uplink_key) {
        Ok(k) => k,
        Err(e) => return done(lines, Outcome::Refused(format!("uplink key: {e}"))),
    };
    match en.key("uplink") {
        Some(k) if k.fingerprint == auth.fingerprint() => lines.push(format!(
            "ok   uplink key {} is the one registered for robot {}",
            auth.key_id(),
            en.robot_id
        )),
        Some(k) => {
            return done(
                lines,
                Outcome::Refused(format!(
                    "{} holds {} but {} is registered (an unfinished rotation?)",
                    ctx.cfg.uplink_key.display(),
                    auth.key_id(),
                    k.key_id
                )),
            )
        }
        None => {
            return done(
                lines,
                Outcome::Refused("enrollment has no uplink key".into()),
            )
        }
    }
    match client::exchange(
        t,
        "GET",
        wire::PATH_RING,
        &[],
        Some((&auth.signing, ctx.now())),
    ) {
        Ok(body) => {
            lines.push("ok   TLS to the SOC (CA bundle, pins, CRLs)".into());
            lines.push("ok   request authentication: the SOC accepts the uplink key".into());
            match Envelope::parse(&body, wire::T_RING)
                .map_err(|e| e.to_string())
                .and_then(|o| soc.verify(&o))
            {
                Ok(id) => {
                    lines.push(format!(
                        "ok   ring information verifies under SOC fleet key {id} (not recorded)"
                    ));
                    done(lines, Outcome::Ok)
                }
                Err(e) => done(
                    lines,
                    Outcome::Refused(format!(
                        "ring information does not verify under a configured SOC fleet key: \
                         {e} (wrong soc.keys?)"
                    )),
                ),
            }
        }
        Err(SocError::Refused {
            status: 404, code, ..
        }) if code == "no_ring" => {
            lines.push("ok   TLS to the SOC (CA bundle, pins, CRLs)".into());
            lines.push("ok   request authentication: the SOC accepts the uplink key".into());
            lines.push(
                "skip SOC answer signature: no ring information published for this robot".into(),
            );
            done(lines, Outcome::Ok)
        }
        Err(SocError::Transport(e)) => {
            done(lines, Outcome::Unreachable(format!("SOC not reached: {e}")))
        }
        Err(e @ SocError::Refused { .. }) => {
            lines.push("ok   TLS to the SOC (CA bundle, pins, CRLs)".into());
            done(
                lines,
                Outcome::Refused(format!(
                    "request authentication: {e} (unknown_key: not registered or retired; \
                     stale_timestamp: fix the unit clock)"
                )),
            )
        }
    }
}
