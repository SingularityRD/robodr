//! LAN delivery from the site depot (`docs/SECURE-DELIVERY.md` §4.1 step
//! 6, Sprint 14a; protocol `robodr_pkg::wire`).
//!
//! * **Mutual TLS** with `robodr_blackbox::tls`: the depot is verified
//!   against its unit CA (`depot.ca_file`) and `depot.server_name`; the
//!   unit's client certificate (`depot.cert_file`, issued at enrolment)
//!   is for its **TPM-resident identity key**: every handshake signature is
//!   made by the TPM (`tpm2_sign`), the key never exists in a file.
//! * **Pull**: the pack stream is written into a hidden staging directory
//!   in `media_dir`, each file bounded by its listed size and checked
//!   against its listed hash, then renamed to `media_dir/depot-lan`, where
//!   the ordinary import treats it as any other untrusted media pack
//!   (verified copy, every signature and hash again).
//! * **Report**: the unit's signed report goes to the depot; the answer
//!   may carry a site lease, which the seal directory verifies and
//!   installs (Sprint 14b).

use crate::config::{Config, DepotCfg};
use crate::engine::Engine;
use crate::sealing::Sealing;
use robodr_pkg::wire::{self, Request};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The media entry the LAN pack lands in.
pub const LAN_PACK: &str = "depot-lan";

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn connect(d: &DepotCfg, sealing: &Sealing) -> Result<Tls, String> {
    let s = sealing.clone();
    let sign: Arc<robodr_blackbox::tls::ExternalSign> = Arc::new(move |dg: &[u8; 32]| {
        s.unit()
            .and_then(|u| u.sign_digest(dg))
            .map_err(|e| format!("identity key: {e}"))
    });
    let tls = robodr_blackbox::tls::load_client_with_signer(
        &robodr_blackbox::tls::ClientTlsFiles {
            ca_file: d.ca_file.clone(),
            cert_chain: Some(d.cert_file.clone()),
            key_file: None,
            server_name: Some(d.server_name.clone()),
            spki_sha256: Vec::new(),
        },
        sign,
    )?;
    let addr = d
        .address
        .to_socket_addrs()
        .map_err(|e| format!("{}: {e}", d.address))?
        .next()
        .ok_or_else(|| format!("{}: no address", d.address))?;
    let deadline = Duration::from_secs(d.deadline_s);
    let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(30))
        .map_err(|e| format!("{}: {e}", d.address))?;
    let _ = sock.set_read_timeout(Some(deadline));
    let _ = sock.set_write_timeout(Some(deadline));
    let name = tls.name_for(&d.server_name)?;
    let conn =
        rustls::ClientConnection::new(tls.config.clone(), name).map_err(|e| e.to_string())?;
    Ok(rustls::StreamOwned::new(conn, sock))
}

fn read_head(s: &mut Tls) -> Result<(u16, u64), String> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while wire::head_end(&head).is_none() {
        if head.len() >= wire::MAX_HEAD {
            return Err("response header too large".into());
        }
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            Ok(_) => return Err("connection closed".into()),
            Err(e) => return Err(robodr_blackbox::tls::describe(&e)),
        }
    }
    wire::parse_response(&head).map_err(|e| e.to_string())
}

fn error_text(s: &mut Tls, len: u64) -> String {
    let mut b = Vec::new();
    let _ = s.take(len.min(4096)).read_to_end(&mut b);
    robodr_pkg::common::trunc(&String::from_utf8_lossy(&b))
}

fn sealing_of(cfg: &Config) -> Result<(DepotCfg, Sealing), String> {
    let d = cfg.depot.clone().ok_or("no depot configuration")?;
    let s = cfg.seal.as_ref().ok_or("no seal configuration")?;
    Ok((d, Sealing::new(s, &cfg.unit.id)))
}

/// The listing line of the last pack pulled (a dot name: never a media
/// entry).
const LAN_LISTING: &str = ".depot-lan.listing";

/// Fetch this unit's pack from the depot into `media_dir/depot-lan`.
/// Returns its path.
pub fn pull(cfg: &Config) -> Result<PathBuf, String> {
    pull_with(cfg, false)?.ok_or_else(|| "nothing pulled".into())
}

/// As [`pull`], but the transfer stops after the listing when it equals
/// the last one pulled and that pack is still in place (the agent's loop:
/// an unchanged pack is not downloaded again). `None`: unchanged.
pub fn pull_if_changed(cfg: &Config) -> Result<Option<PathBuf>, String> {
    pull_with(cfg, true)
}

fn pull_with(cfg: &Config, skip_same: bool) -> Result<Option<PathBuf>, String> {
    let (d, sealing) = sealing_of(cfg)?;
    let mut s = connect(&d, &sealing)?;
    s.write_all(&wire::encode_request(Request::Pack, &d.server_name))
        .map_err(|e| robodr_blackbox::tls::describe(&e))?;
    let (status, len) = read_head(&mut s)?;
    if status != 200 {
        return Err(format!(
            "depot answered {status}: {}",
            error_text(&mut s, len)
        ));
    }
    // The listing line.
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if line.len() > wire::MAX_LISTING {
            return Err("pack listing too large".into());
        }
        s.read_exact(&mut b).map_err(|e| e.to_string())?;
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    let (listing, total) = wire::parse_listing(&line).map_err(|e| e.to_string())?;
    let dst = cfg.media_dir.join(LAN_PACK);
    let saved = cfg.media_dir.join(LAN_LISTING);
    if skip_same
        && crate::fsx::is_real_dir(&dst)
        && robodr_release::fsio::read_capped(&saved, wire::MAX_LISTING).is_ok_and(|b| b == line)
    {
        return Ok(None);
    }
    if total > d.max_pack_mb.saturating_mul(1024 * 1024) {
        return Err(format!(
            "pack of {total} bytes is larger than depot.max_pack_mb"
        ));
    }
    if len != line.len() as u64 + 1 + total {
        return Err("pack stream length does not match its listing".into());
    }
    let stage = cfg.media_dir.join(format!(
        ".lan-{}-{}",
        std::process::id(),
        robodr_blackbox::crypto::to_hex(&rand8())
    ));
    let r = (|| -> Result<(), String> {
        std::fs::create_dir(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
        for f in &listing.files {
            // Paths are the pack grammar only (no traversal is expressible).
            let to = stage.join(&f.path);
            if let Some(p) = to.parent() {
                std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
            }
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&to)
                .map_err(|e| format!("{}: {e}", to.display()))?;
            let mut h = robodr_blackbox::crypto::Sha256::new();
            let mut left = f.size;
            let mut buf = vec![0u8; 64 * 1024];
            while left > 0 {
                let n = (left as usize).min(buf.len());
                let chunk = buf.get_mut(..n).unwrap_or_default();
                s.read_exact(chunk).map_err(|e| e.to_string())?;
                h.update(chunk);
                out.write_all(chunk).map_err(|e| e.to_string())?;
                left -= n as u64;
            }
            if robodr_blackbox::crypto::to_hex(&h.finalize()) != f.sha256 {
                return Err(format!("{}: hash differs from the listing", f.path));
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        let _ = crate::fsx::remove_any(&stage);
        return Err(e);
    }
    let _ = crate::fsx::remove_any(&dst);
    let _ = std::fs::remove_file(&saved);
    std::fs::rename(&stage, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    // Best effort: without it the next loop downloads the pack again.
    let _ = std::fs::write(&saved, &line);
    Ok(Some(dst))
}

fn rand8() -> [u8; 8] {
    let mut b = [0u8; 8];
    let _ = robodr_blackbox::crypto::fill_random(&mut b);
    b
}

/// Send this unit's signed report; install a lease the depot answers with.
/// Returns whether a lease was installed.
pub fn report(engine: &mut Engine) -> Result<bool, String> {
    let (d, sealing) = sealing_of(engine.config())?;
    let body = engine.unit_report().map_err(|e| e.to_string())?;
    let mut s = connect(&d, &sealing)?;
    s.write_all(&wire::encode_request(
        Request::Report(body.len()),
        &d.server_name,
    ))
    .and_then(|()| s.write_all(&body))
    .map_err(|e| robodr_blackbox::tls::describe(&e))?;
    let (status, len) = read_head(&mut s)?;
    if status != 200 {
        return Err(format!(
            "depot answered {status}: {}",
            error_text(&mut s, len)
        ));
    }
    if len > 64 * 1024 {
        return Err("answer too large".into());
    }
    let mut b = vec![0u8; len as usize];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
    match v.get("lease") {
        Some(l) if !l.is_null() => {
            let l: robodr_seal::lease::Lease =
                serde_json::from_value(l.clone()).map_err(|e| e.to_string())?;
            let bytes = l.to_bytes().map_err(|e| e.to_string())?;
            engine.install_lease(&bytes).map_err(|e| e.to_string())?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// A lease file in a media pack (Sprint 14b; optional `lease.json`):
/// read bounded, verified and installed by the seal directory.
pub fn lease_from_pack(engine: &mut Engine, pack: &Path) -> Result<bool, String> {
    let p = pack.join("lease.json");
    match std::fs::symlink_metadata(&p) {
        Err(_) => return Ok(false),
        Ok(m) if !m.file_type().is_file() => return Err("lease.json: not a regular file".into()),
        Ok(_) => {}
    }
    let b = robodr_release::fsio::read_capped(&p, robodr_seal::lease::MAX_LEASE_BYTES)
        .map_err(|e| e.to_string())?;
    // Each distinct lease file once per run (refused ones too: the
    // refusal is journaled once).
    let h = robodr_blackbox::crypto::to_hex(&robodr_blackbox::crypto::sha256(&b));
    if !engine.leases_tried.insert(h) {
        return Ok(false);
    }
    engine.install_lease(&b).map_err(|e| e.to_string())?;
    Ok(true)
}
