//! Key wraps (`docs/SECURE-DELIVERY.md` §7.1, §7.3): a 32-byte key
//! (a content key `CK`, or a runtime-volume key) encrypted to one
//! recipient's public key.
//!
//! ```text
//! X25519 (depot wrapping keys, units without a TPM):
//!   0x01 || ephemeral public (32) || nonce (24) || XChaCha20-Poly1305(key) (32 + 16)   105 bytes
//! P-256 (a unit's TPM-resident UWK; the unit computes Z with tpm2_ecdhzgen):
//!   0x02 || ephemeral public, SEC1 uncompressed (65) || nonce (24) || ciphertext (48)  138 bytes
//! ```
//!
//! `KEK = HKDF-SHA256(salt = "robodr-seal/wrap/v1", ikm = Z, info = alg ||
//! ephemeral public || recipient public || context)` where `Z` is the
//! ECDH shared secret (the x-coordinate for P-256). The **context** says
//! what the key is for and is also the AEAD's associated data
//! ([`WrapContext`]): a depot wrap is bound to the RPK's `seal_id`, a unit
//! wrap to the unit id and the RPK digest, a volume-key wrap to the unit
//! id. A wrap moved to another unit, RPK or purpose, or for another
//! recipient key, fails authentication. A fresh ephemeral key per wrap
//! makes every wrap different, and a low-order X25519 point (an all-zero
//! shared secret) is refused.

use crate::{invalid, unauthentic, ErrorKind, SealError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Algorithm byte: X25519.
pub const ALG_X25519: u8 = 0x01;
/// Algorithm byte: P-256 (TPM UWK).
pub const ALG_P256: u8 = 0x02;
/// Wrap length, X25519.
pub const X25519_WRAP_LEN: usize = 1 + 32 + 24 + 48;
/// Wrap length, P-256.
pub const P256_WRAP_LEN: usize = 1 + 65 + 24 + 48;
/// P-256 public key length (SEC1 uncompressed).
pub const P256_PUBLIC_LEN: usize = 65;

const KDF_SALT: &[u8] = b"robodr-seal/wrap/v1";

/// What a wrapped key is for (bound into the wrap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapContext {
    /// The content key of the sealed RPK with this `seal_id`, wrapped by
    /// the release to a depot (manifest `seal.depot_wraps`).
    Depot { seal_id: [u8; 32] },
    /// The content key of RPK `rpk_digest` (hex), re-wrapped by the depot
    /// to `unit` (deployment `wrapped_keys`).
    Unit { unit: String, rpk_digest: String },
    /// The runtime-volume key of `unit` (§7.4).
    Volume { unit: String },
    /// A throw-away key that proves the unit can unseal right now (policy
    /// commit, status).
    Probe { unit: String },
}

impl WrapContext {
    /// The associated data / HKDF context bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let lp = |b: &mut Vec<u8>, s: &[u8]| {
            b.extend_from_slice(&(s.len() as u16).to_be_bytes());
            b.extend_from_slice(s);
        };
        match self {
            WrapContext::Depot { seal_id } => {
                b.extend_from_slice(b"robodr-seal/depot-wrap/v1\0");
                b.extend_from_slice(seal_id);
            }
            WrapContext::Unit { unit, rpk_digest } => {
                b.extend_from_slice(b"robodr-seal/unit-wrap/v1\0");
                lp(&mut b, unit.as_bytes());
                lp(&mut b, rpk_digest.as_bytes());
            }
            WrapContext::Volume { unit } => {
                b.extend_from_slice(b"robodr-seal/volume-key/v1\0");
                lp(&mut b, unit.as_bytes());
            }
            WrapContext::Probe { unit } => {
                b.extend_from_slice(b"robodr-seal/probe/v1\0");
                lp(&mut b, unit.as_bytes());
            }
        }
        b
    }
}

/// A recipient's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    X25519([u8; 32]),
    /// SEC1 uncompressed point.
    P256([u8; P256_PUBLIC_LEN]),
}

impl Recipient {
    pub fn alg(&self) -> u8 {
        match self {
            Recipient::X25519(_) => ALG_X25519,
            Recipient::P256(_) => ALG_P256,
        }
    }

    pub fn public_bytes(&self) -> &[u8] {
        match self {
            Recipient::X25519(p) => p,
            Recipient::P256(p) => p,
        }
    }

    /// `sha256:<hex>` of the raw public key.
    pub fn fingerprint(&self) -> String {
        format!(
            "sha256:{}",
            crate::to_hex(&robodr_blackbox::crypto::sha256(self.public_bytes()))
        )
    }

    /// A P-256 recipient from SEC1 uncompressed bytes (checked on the curve).
    pub fn p256(b: &[u8]) -> Result<Self, SealError> {
        let a: [u8; P256_PUBLIC_LEN] = b
            .try_into()
            .map_err(|_| invalid("P-256 public key must be 65 bytes (SEC1 uncompressed)"))?;
        if a[0] != 0x04 || p256::PublicKey::from_sec1_bytes(&a).is_err() {
            return Err(invalid("not a P-256 public key"));
        }
        Ok(Recipient::P256(a))
    }
}

fn kek(alg: u8, z: &[u8], eph: &[u8], recipient: &[u8], ctx: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), z);
    let mut info = Vec::with_capacity(1 + eph.len() + recipient.len() + ctx.len());
    info.push(alg);
    info.extend_from_slice(eph);
    info.extend_from_slice(recipient);
    info.extend_from_slice(ctx);
    let mut k = Zeroizing::new([0u8; 32]);
    let _ = hk.expand(&info, &mut k[..]);
    k
}

fn x25519_shared(secret: &[u8; 32], public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let s = x25519_dalek::StaticSecret::from(*secret);
    let shared = s.diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(unauthentic(
            "X25519: low-order public key (no shared secret)",
        ));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// The x-coordinate of `secret * public` on P-256.
pub fn p256_shared(
    secret: &p256::SecretKey,
    public: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let pk = p256::PublicKey::from_sec1_bytes(public).map_err(|_| invalid("not a P-256 point"))?;
    let s = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), pk.as_affine());
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(s.raw_secret_bytes());
    Ok(z)
}

/// A fresh random P-256 secret key.
pub fn p256_random() -> Result<p256::SecretKey, SealError> {
    for _ in 0..8 {
        let b = crate::random32()?;
        if let Ok(k) = p256::SecretKey::from_slice(&b[..]) {
            return Ok(k);
        }
    }
    Err(SealError::new(
        ErrorKind::Unavailable,
        "could not draw a P-256 scalar",
    ))
}

/// SEC1 uncompressed bytes of a P-256 public key.
pub fn p256_public_bytes(k: &p256::PublicKey) -> [u8; P256_PUBLIC_LEN] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let mut out = [0u8; P256_PUBLIC_LEN];
    let p = k.to_encoded_point(false);
    out.copy_from_slice(p.as_bytes());
    out
}

/// Wrap `key` (32 bytes) to `to` for `ctx`.
pub fn wrap(to: &Recipient, key: &[u8; 32], ctx: &WrapContext) -> Result<Vec<u8>, SealError> {
    let ctxb = ctx.bytes();
    let (eph, z): (Vec<u8>, Zeroizing<[u8; 32]>) = match to {
        Recipient::X25519(public) => {
            let s = crate::random32()?;
            let eph = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*s));
            (eph.as_bytes().to_vec(), x25519_shared(&s, public)?)
        }
        Recipient::P256(public) => {
            let s = p256_random()?;
            let eph = p256_public_bytes(&s.public_key());
            (eph.to_vec(), p256_shared(&s, public)?)
        }
    };
    let k = kek(to.alg(), &z[..], &eph, to.public_bytes(), &ctxb);
    let nonce = crate::random32()?;
    let ct = XChaCha20Poly1305::new((&*k).into())
        .encrypt(
            XNonce::from_slice(&nonce[..24]),
            Payload {
                msg: key,
                aad: &ctxb,
            },
        )
        .map_err(|_| invalid("wrap failed"))?;
    let mut out = Vec::with_capacity(P256_WRAP_LEN);
    out.push(to.alg());
    out.extend_from_slice(&eph);
    out.extend_from_slice(&nonce[..24]);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// A parsed wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrap<'a> {
    pub alg: u8,
    pub ephemeral: &'a [u8],
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
}

/// Parse wrap bytes (length and algorithm only; the ephemeral key is
/// checked when it is used).
pub fn parse(w: &[u8]) -> Result<Wrap<'_>, SealError> {
    let eph_len = match (w.first(), w.len()) {
        (Some(&ALG_X25519), X25519_WRAP_LEN) => 32,
        (Some(&ALG_P256), P256_WRAP_LEN) => P256_PUBLIC_LEN,
        (Some(&ALG_X25519), _) | (Some(&ALG_P256), _) => {
            return Err(unauthentic("wrap has the wrong length for its algorithm"))
        }
        _ => return Err(invalid("unknown wrap algorithm")),
    };
    let (eph, rest) = w[1..].split_at(eph_len);
    let (nonce, ct) = rest.split_at(24);
    Ok(Wrap {
        alg: w[0],
        ephemeral: eph,
        nonce,
        ciphertext: ct,
    })
}

/// The recipient side of a wrap: holds (or reaches) the private key.
pub trait Unwrapper {
    /// The recipient's public key (bound into every wrap to it).
    fn recipient(&self) -> Recipient;
    /// The ECDH shared secret with `ephemeral` (x-coordinate for P-256).
    /// For a TPM-resident key this is where the TPM enforces its policy.
    fn shared(&self, ephemeral: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError>;
}

/// Unwrap: the 32-byte key, only if the wrap authenticates for this
/// recipient and context. The algorithm and length are checked before the
/// recipient's key is used (a TPM is not asked for a wrap that cannot be
/// its own).
pub fn unwrap(
    by: &dyn Unwrapper,
    w: &[u8],
    ctx: &WrapContext,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let p = parse(w)?;
    let me = by.recipient();
    if p.alg != me.alg() {
        return Err(unauthentic("wrap is for another kind of recipient key"));
    }
    if p.alg == ALG_P256 && p256::PublicKey::from_sec1_bytes(p.ephemeral).is_err() {
        return Err(unauthentic("wrap's ephemeral key is not a P-256 point"));
    }
    let z = by.shared(p.ephemeral)?;
    let ctxb = ctx.bytes();
    let k = kek(p.alg, &z[..], p.ephemeral, me.public_bytes(), &ctxb);
    let pt = Zeroizing::new(
        XChaCha20Poly1305::new((&*k).into())
            .decrypt(
                XNonce::from_slice(p.nonce),
                Payload {
                    msg: p.ciphertext,
                    aad: &ctxb,
                },
            )
            .map_err(|_| {
                unauthentic(
                    "wrap does not authenticate (tampered, or for another unit, RPK, purpose or \
                     key)",
                )
            })?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    if pt.len() != 32 {
        return Err(unauthentic("wrapped key is not 32 bytes"));
    }
    out.copy_from_slice(&pt);
    Ok(out)
}

/// An X25519 private key held in memory (a depot wrapping key, or the
/// UWK of a unit without a TPM).
pub struct X25519Secret(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519Secret(..)")
    }
}

impl X25519Secret {
    pub fn generate() -> Result<Self, SealError> {
        Ok(Self(crate::random32()?))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, SealError> {
        let a: [u8; 32] = b
            .try_into()
            .map_err(|_| invalid("X25519 secret must be 32 bytes"))?;
        Ok(Self(Zeroizing::new(a)))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public(&self) -> [u8; 32] {
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*self.0)).as_bytes()
    }
}

impl Unwrapper for X25519Secret {
    fn recipient(&self) -> Recipient {
        Recipient::X25519(self.public())
    }

    fn shared(&self, ephemeral: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
        let e: [u8; 32] = ephemeral
            .try_into()
            .map_err(|_| unauthentic("X25519 ephemeral key must be 32 bytes"))?;
        x25519_shared(&self.0, &e)
    }
}

/// A P-256 private key held in memory: the software stand-in of a
/// TPM-resident UWK, for tests and for the depot's own checks.
pub struct P256Secret(pub p256::SecretKey);

impl Unwrapper for P256Secret {
    fn recipient(&self) -> Recipient {
        Recipient::P256(p256_public_bytes(&self.0.public_key()))
    }

    fn shared(&self, ephemeral: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
        p256_shared(&self.0, ephemeral)
    }
}

/// Unwrap with `from` and wrap again to `to` (the depot's re-wrap, §7.3).
pub fn rewrap(
    from: &dyn Unwrapper,
    w: &[u8],
    from_ctx: &WrapContext,
    to: &Recipient,
    to_ctx: &WrapContext,
) -> Result<Vec<u8>, SealError> {
    let k = unwrap(from, w, from_ctx)?;
    wrap(to, &k, to_ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_ctx(u: &str) -> WrapContext {
        WrapContext::Unit {
            unit: u.into(),
            rpk_digest: "ab".repeat(32),
        }
    }

    #[test]
    fn x25519_and_p256_round_trip() {
        let key = [9u8; 32];
        let x = X25519Secret::generate().unwrap();
        let w = wrap(&x.recipient(), &key, &unit_ctx("ugv-07")).unwrap();
        assert_eq!(w.len(), X25519_WRAP_LEN);
        assert_eq!(*unwrap(&x, &w, &unit_ctx("ugv-07")).unwrap(), key);
        let p = P256Secret(p256_random().unwrap());
        let w2 = wrap(&p.recipient(), &key, &unit_ctx("ugv-07")).unwrap();
        assert_eq!(w2.len(), P256_WRAP_LEN);
        assert_eq!(*unwrap(&p, &w2, &unit_ctx("ugv-07")).unwrap(), key);
        // Fresh ephemeral and nonce each time.
        assert_ne!(w, wrap(&x.recipient(), &key, &unit_ctx("ugv-07")).unwrap());
    }

    #[test]
    fn wrong_unit_context_key_or_tamper_is_refused() {
        let key = [9u8; 32];
        let a = P256Secret(p256_random().unwrap());
        let b = P256Secret(p256_random().unwrap());
        let w = wrap(&a.recipient(), &key, &unit_ctx("ugv-07")).unwrap();
        // Another unit's key (a media pack moved to another unit).
        assert_eq!(
            unwrap(&b, &w, &unit_ctx("ugv-07")).unwrap_err().kind,
            ErrorKind::Unauthentic
        );
        // Right key, wrap re-labelled for another unit or RPK or purpose.
        assert!(unwrap(&a, &w, &unit_ctx("ugv-08")).is_err());
        assert!(unwrap(
            &a,
            &w,
            &WrapContext::Unit {
                unit: "ugv-07".into(),
                rpk_digest: "cd".repeat(32)
            }
        )
        .is_err());
        assert!(unwrap(
            &a,
            &w,
            &WrapContext::Volume {
                unit: "ugv-07".into()
            }
        )
        .is_err());
        // Every byte flipped, every truncation.
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x80;
            assert!(unwrap(&a, &t, &unit_ctx("ugv-07")).is_err(), "flip {i}");
        }
        for n in 0..w.len() {
            assert!(unwrap(&a, &w[..n], &unit_ctx("ugv-07")).is_err());
        }
        // An X25519 wrap is not a P-256 one.
        let x = X25519Secret::generate().unwrap();
        let wx = wrap(&x.recipient(), &key, &unit_ctx("ugv-07")).unwrap();
        assert!(unwrap(&a, &wx, &unit_ctx("ugv-07")).is_err());
    }

    #[test]
    fn low_order_x25519_points_are_refused() {
        let x = X25519Secret::generate().unwrap();
        // The identity (all zero) and a small-order point.
        for eph in [[0u8; 32], {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        }] {
            let mut w = vec![ALG_X25519];
            w.extend_from_slice(&eph);
            w.extend_from_slice(&[0u8; 72]);
            assert_eq!(
                unwrap(&x, &w, &unit_ctx("u")).unwrap_err().kind,
                ErrorKind::Unauthentic
            );
        }
        // Wrapping to a low-order recipient key is refused as well.
        assert!(wrap(&Recipient::X25519([0u8; 32]), &[1; 32], &unit_ctx("u")).is_err());
    }

    #[test]
    fn rewrap_depot_to_unit() {
        let key = [3u8; 32];
        let depot = X25519Secret::generate().unwrap();
        let unit = P256Secret(p256_random().unwrap());
        let dctx = WrapContext::Depot { seal_id: [1; 32] };
        let w = wrap(&depot.recipient(), &key, &dctx).unwrap();
        let uw = rewrap(&depot, &w, &dctx, &unit.recipient(), &unit_ctx("ugv-07")).unwrap();
        assert_eq!(*unwrap(&unit, &uw, &unit_ctx("ugv-07")).unwrap(), key);
        // A depot wrap of another RPK (other seal_id) is refused.
        assert!(rewrap(
            &depot,
            &w,
            &WrapContext::Depot { seal_id: [2; 32] },
            &unit.recipient(),
            &unit_ctx("ugv-07")
        )
        .is_err());
    }

    #[test]
    fn recipient_checks() {
        assert!(Recipient::p256(&[4u8; 65]).is_err());
        assert!(Recipient::p256(&[4u8; 64]).is_err());
        let p = P256Secret(p256_random().unwrap());
        let r = p.recipient();
        assert_eq!(Recipient::p256(r.public_bytes()).unwrap(), r);
        assert!(r.fingerprint().starts_with("sha256:"));
    }
}
