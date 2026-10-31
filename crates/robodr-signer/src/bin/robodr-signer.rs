//! `robodr-signer`: check a key provider before a ceremony, classify a
//! systemd encrypted credential.
//!
//! ```text
//! robodr-signer check --key KEY_OR_SIGNER_FILE
//! robodr-signer credential --file CREDENTIAL
//! ```
//!
//! Exit codes: 0 ok, 1 error, 2 usage.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::path::Path;
use std::process::ExitCode;

use robodr_blackbox::Signer;
use serde_json::json;

const USAGE: &str = "\
usage:
  robodr-signer check --key KEY_OR_SIGNER_FILE
      load a robodr-blackbox secret key file or a robodr-signer/v1 signer
      file, sign a random challenge (an external signer is really run: PIN,
      touch) and verify it under the pinned public key; prints key id,
      backend and fingerprint as JSON
  robodr-signer credential --file CREDENTIAL
      classify a systemd encrypted credential (tpm2, host+tpm2, host, null,
      unknown) by its header, without decrypting it";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = match refs.as_slice() {
        ["check", "--key", k] => check(Path::new(k)),
        ["credential", "--file", f] => credential(Path::new(f)),
        ["--help"] | ["-h"] | ["help"] => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("robodr-signer: {e}");
            ExitCode::from(1)
        }
    }
}

fn check(key: &Path) -> Result<serde_json::Value, String> {
    let s = robodr_signer::load(key)?;
    let nonce = robodr_blackbox::sign_ed25519::random_seed().map_err(|e| e.to_string())?;
    let mut msg = b"robodr-signer/check/v1\0".to_vec();
    msg.extend_from_slice(&nonce);
    // KeySigner::sign verifies the signature under the pinned key.
    s.sign(&msg).map_err(|e| e.to_string())?;
    Ok(json!({
        "key_id": s.key_id(),
        "backend": s.backend().as_str(),
        "fingerprint": s.fingerprint(),
        "public_key_hex": robodr_blackbox::crypto::to_hex(&s.public_key()),
        "signature_verified": true,
    }))
}

fn credential(file: &Path) -> Result<serde_json::Value, String> {
    let seal = robodr_signer::credential::classify_file(file)?;
    Ok(json!({
        "file": file.display().to_string(),
        "seal": seal.as_str(),
        "tpm2_bound": seal.tpm2_bound(),
    }))
}
