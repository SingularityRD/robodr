//! The unit's TPM identity (Sprint 14a, `docs/SECURE-DELIVERY.md` §8),
//! driven through `tpm2-tools` like [`crate::tpm`]:
//!
//! * the **EK** (RSA 2048, the TCG default template, recreated with
//!   `tpm2_createek`) and its certificate from NV index
//!   [`EK_CERT_NV_RSA`], written by the TPM's manufacturer;
//! * the **AK**, a restricted ECDSA P-256 signing key under the EK
//!   (`tpm2_createak`); its blobs are kept in the seal directory and it is
//!   loaded under the EK with a `PolicySecret(endorsement)` session;
//! * the **UIK** (unit identity key), a non-restricted ECDSA P-256 signing
//!   key under the SRK ([`UIK_ATTRIBUTES`]): the unit's TLS client key and
//!   the key that signs its install reports and lease requests. Its
//!   private part never leaves the TPM;
//! * `TPM2_Certify` (the AK certifies the UWK and the UIK), `TPM2_Quote`,
//!   `TPM2_ActivateCredential`, `TPM2_Sign`, `TPM2_ReadClock` and NV
//!   counters ([`crate::nvcounter`]).
//!
//! Each operation loads what it needs into a fresh tmpfs work directory
//! and flushes transient objects afterwards.

use crate::lease::{parse_readclock, TpmTime};
use crate::tpm::{hx, Tpm, WorkDir};
use crate::{invalid, io_err, ErrorKind, SealError};
use std::fs;
use zeroize::Zeroizing;

/// PCR index and SHA-256 value pairs, in index order.
pub type PcrValues = Vec<(u8, [u8; 32])>;

/// NV index of the RSA 2048 EK certificate (TCG EK Credential Profile).
pub const EK_CERT_NV_RSA: u32 = 0x01c0_0002;
/// `tpm2_create -a` of the UIK.
pub const UIK_ATTRIBUTES: &str = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda";
/// `TPMA_NV` of an anchor counter once written (as the erase epoch).
pub const COUNTER_NV_ATTRIBUTES: u32 = crate::policy::EPOCH_NV_ATTRIBUTES;
pub const COUNTER_NV_DEFINE: &str = crate::policy::EPOCH_NV_DEFINE;

/// A signed TPM attestation: `TPMS_ATTEST` bytes and DER signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub attest: Vec<u8>,
    pub sig: Vec<u8>,
}

/// State of an NV counter index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    /// No such index.
    Undefined,
    /// Defined, never incremented (unreadable).
    Unwritten,
    Value(u64),
}

impl Tpm {
    fn ek(&self, w: &WorkDir) -> Result<(String, Vec<u8>), SealError> {
        let ctx = w.path("ek.ctx").display().to_string();
        let pu = w.path("ek.pub");
        self.must(
            "tpm2_createek",
            &[
                "-c".into(),
                ctx.clone(),
                "-G".into(),
                "rsa".into(),
                "-u".into(),
                pu.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "create the EK",
        )?;
        let b = fs::read(&pu).map_err(|e| io_err(&pu, e))?;
        Ok((ctx, b))
    }

    /// The EK public area (`TPM2B_PUBLIC`).
    pub fn ek_public(&self) -> Result<Vec<u8>, SealError> {
        let w = self.work()?;
        Ok(self.ek(&w)?.1)
    }

    /// The EK certificate (DER) from [`EK_CERT_NV_RSA`], if the
    /// manufacturer stored one.
    pub fn ek_certificate(&self) -> Result<Option<Vec<u8>>, SealError> {
        let Some(p) = self.nv_public(EK_CERT_NV_RSA)? else {
            return Ok(None);
        };
        let w = self.work()?;
        let out = w.path("ekcert.der");
        self.must(
            "tpm2_nvread",
            &[
                hx(EK_CERT_NV_RSA),
                "-s".into(),
                p.size.to_string(),
                "-o".into(),
                out.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "read the EK certificate",
        )?;
        let mut b = fs::read(&out).map_err(|e| io_err(&out, e))?;
        // The index may be padded after the DER certificate.
        if b.len() >= 4 && b[0] == 0x30 && b[1] == 0x82 {
            let n = 4 + usize::from(u16::from_be_bytes([b[2], b[3]]));
            if n <= b.len() {
                b.truncate(n);
            }
        }
        Ok(Some(b))
    }

    /// Create an AK under the EK: `(public, private)` blobs.
    pub fn create_ak(&self) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let w = self.work()?;
        let (ek, _) = self.ek(&w)?;
        let (pu, pr) = (w.path("ak.pub"), w.path("ak.priv"));
        let r = self.must(
            "tpm2_createak",
            &[
                "-C".into(),
                ek,
                "-c".into(),
                w.path("ak.ctx").display().to_string(),
                "-G".into(),
                "ecc".into(),
                "-g".into(),
                "sha256".into(),
                "-s".into(),
                "ecdsa".into(),
                "-u".into(),
                pu.display().to_string(),
                "-r".into(),
                pr.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "create the AK",
        );
        self.flush_sessions();
        r?;
        Ok((
            fs::read(&pu).map_err(|e| io_err(&pu, e))?,
            fs::read(&pr).map_err(|e| io_err(&pr, e))?,
        ))
    }

    /// An endorsement-hierarchy policy session (`PolicySecret(e)`), for
    /// using the EK as a parent or for activation.
    fn endorsement_session(&self, w: &WorkDir, name: &str) -> Result<String, SealError> {
        let s = w.path(name).display().to_string();
        self.must(
            "tpm2_startauthsession",
            &["--policy-session".into(), "-S".into(), s.clone()],
            None,
            ErrorKind::Unavailable,
            "endorsement session",
        )?;
        self.must(
            "tpm2_policysecret",
            &["-S".into(), s.clone(), "-c".into(), "e".into()],
            None,
            ErrorKind::Unavailable,
            "PolicySecret(endorsement)",
        )?;
        Ok(s)
    }

    /// Load the AK under the EK; the EK context and the AK context.
    fn load_ak(&self, w: &WorkDir, pu: &[u8], pr: &[u8]) -> Result<(String, String), SealError> {
        let (ek, _) = self.ek(w)?;
        let s = self.endorsement_session(w, "ak-load.session")?;
        let a = w.write("ak.pub", pu)?;
        let b = w.write("ak.priv", pr)?;
        let ctx = w.path("ak.ctx").display().to_string();
        let r = self.must(
            "tpm2_load",
            &[
                "-C".into(),
                ek.clone(),
                "-u".into(),
                a,
                "-r".into(),
                b,
                "-c".into(),
                ctx.clone(),
                "-P".into(),
                format!("session:{s}"),
            ],
            None,
            ErrorKind::Unavailable,
            "load the AK (another TPM?)",
        );
        self.flush_sessions();
        r?;
        Ok((ek, ctx))
    }

    /// Create the UIK under the SRK: `(public, private)` blobs.
    pub fn create_uik(&self) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let w = self.work()?;
        let (pu, pr) = (w.path("uik.pub"), w.path("uik.priv"));
        self.must(
            "tpm2_create",
            &[
                "-C".into(),
                hx(self.cfg.srk),
                "-G".into(),
                "ecc256:ecdsa-sha256".into(),
                "-a".into(),
                UIK_ATTRIBUTES.into(),
                "-u".into(),
                pu.display().to_string(),
                "-r".into(),
                pr.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "create the unit identity key",
        )?;
        Ok((
            fs::read(&pu).map_err(|e| io_err(&pu, e))?,
            fs::read(&pr).map_err(|e| io_err(&pr, e))?,
        ))
    }

    fn load_under_srk(
        &self,
        w: &WorkDir,
        stem: &str,
        pu: &[u8],
        pr: &[u8],
    ) -> Result<String, SealError> {
        let a = w.write(&format!("{stem}.pub"), pu)?;
        let b = w.write(&format!("{stem}.priv"), pr)?;
        let ctx = w.path(&format!("{stem}.ctx")).display().to_string();
        self.must(
            "tpm2_load",
            &[
                "-C".into(),
                hx(self.cfg.srk),
                "-u".into(),
                a,
                "-r".into(),
                b,
                "-c".into(),
                ctx.clone(),
            ],
            None,
            ErrorKind::Unavailable,
            "load a key under the SRK (another TPM, or the SRK changed)",
        )?;
        Ok(ctx)
    }

    /// `TPM2_Certify` of the objects `(stem, public, private)` (loaded
    /// under the SRK) by the AK.
    pub fn certify_with_ak(
        &self,
        ak: (&[u8], &[u8]),
        objects: &[(&str, &[u8], &[u8])],
    ) -> Result<Vec<Signed>, SealError> {
        let w = self.work()?;
        let (_, akc) = self.load_ak(&w, ak.0, ak.1)?;
        let mut out = Vec::new();
        for (stem, pu, pr) in objects {
            let c = self.load_under_srk(&w, stem, pu, pr)?;
            let (a, s) = (
                w.path(&format!("{stem}.attest")),
                w.path(&format!("{stem}.sig")),
            );
            self.must(
                "tpm2_certify",
                &[
                    "-c".into(),
                    c,
                    "-C".into(),
                    akc.clone(),
                    "-g".into(),
                    "sha256".into(),
                    "-o".into(),
                    a.display().to_string(),
                    "-s".into(),
                    s.display().to_string(),
                    "-f".into(),
                    "plain".into(),
                ],
                None,
                ErrorKind::Unavailable,
                "certify with the AK",
            )?;
            out.push(Signed {
                attest: fs::read(&a).map_err(|e| io_err(&a, e))?,
                sig: fs::read(&s).map_err(|e| io_err(&s, e))?,
            });
        }
        Ok(out)
    }

    /// `TPM2_Quote` of SHA-256 `pcrs` with qualifying data `nonce`, and the
    /// PCR values (in index order).
    pub fn quote(
        &self,
        ak: (&[u8], &[u8]),
        pcrs: &[u8],
        nonce: &[u8],
    ) -> Result<(Signed, PcrValues), SealError> {
        if pcrs.is_empty() || nonce.is_empty() || nonce.len() > 64 {
            return Err(invalid("quote: PCRs and a 1..=64 byte nonce"));
        }
        let w = self.work()?;
        let (_, akc) = self.load_ak(&w, ak.0, ak.1)?;
        let list: Vec<String> = pcrs.iter().map(u8::to_string).collect();
        let sel = format!("sha256:{}", list.join(","));
        let (m, s, v) = (w.path("q.msg"), w.path("q.sig"), w.path("q.pcrs"));
        self.must(
            "tpm2_quote",
            &[
                "-c".into(),
                akc,
                "-l".into(),
                sel.clone(),
                "-q".into(),
                crate::to_hex(nonce),
                "-m".into(),
                m.display().to_string(),
                "-s".into(),
                s.display().to_string(),
                "-f".into(),
                "plain".into(),
                "-g".into(),
                "sha256".into(),
            ],
            None,
            ErrorKind::Unavailable,
            "quote",
        )?;
        self.must(
            "tpm2_pcrread",
            &[sel, "-o".into(), v.display().to_string()],
            None,
            ErrorKind::Unavailable,
            "read PCRs",
        )?;
        let raw = fs::read(&v).map_err(|e| io_err(&v, e))?;
        let mut sorted = pcrs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if raw.len() != 32 * sorted.len() {
            return Err(SealError::new(ErrorKind::Unavailable, "tpm2_pcrread: size"));
        }
        let values = sorted
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&raw[32 * i..32 * i + 32]);
                (*p, a)
            })
            .collect();
        Ok((
            Signed {
                attest: fs::read(&m).map_err(|e| io_err(&m, e))?,
                sig: fs::read(&s).map_err(|e| io_err(&s, e))?,
            },
            values,
        ))
    }

    /// `TPM2_ActivateCredential`: the secret the depot sealed to this
    /// TPM's EK for the object named like the AK. Comes back on a pipe.
    pub fn activate(
        &self,
        ak: (&[u8], &[u8]),
        credential: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let w = self.work()?;
        let (ek, akc) = self.load_ak(&w, ak.0, ak.1)?;
        let cred = w.write("cred.in", credential)?;
        let s = self.endorsement_session(&w, "activate.session")?;
        // The work directory is tmpfs (checked); the challenge secret is
        // single-use.
        let out = w.path("cred.out");
        let r = self.must(
            "tpm2_activatecredential",
            &[
                "-c".into(),
                akc,
                "-C".into(),
                ek,
                "-i".into(),
                cred,
                "-o".into(),
                out.display().to_string(),
                "-P".into(),
                format!("session:{s}"),
            ],
            None,
            ErrorKind::Unauthentic,
            "activate the credential (not this TPM's EK, or not this AK)",
        );
        self.flush_sessions();
        r?;
        let b = Zeroizing::new(fs::read(&out).map_err(|e| io_err(&out, e))?);
        let _ = fs::remove_file(&out);
        Ok(b)
    }

    /// ECDSA P-256 signature (DER) by the UIK over a SHA-256 digest.
    pub fn sign_digest(
        &self,
        uik: (&[u8], &[u8]),
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, SealError> {
        let w = self.work()?;
        let c = self.load_under_srk(&w, "uik", uik.0, uik.1)?;
        let d = w.write("digest", digest)?;
        let out = w.path("sig");
        self.must(
            "tpm2_sign",
            &[
                "-c".into(),
                c,
                "-g".into(),
                "sha256".into(),
                "-d".into(),
                "-f".into(),
                "plain".into(),
                "-o".into(),
                out.display().to_string(),
                d,
            ],
            None,
            ErrorKind::Unavailable,
            "sign with the unit identity key",
        )?;
        fs::read(&out).map_err(|e| io_err(&out, e))
    }

    /// The TPM's clock and reset count.
    pub fn read_clock(&self) -> Result<TpmTime, SealError> {
        let o = self.must(
            "tpm2_readclock",
            &[],
            None,
            ErrorKind::Unavailable,
            "read the TPM clock",
        )?;
        parse_readclock(&String::from_utf8_lossy(&o.stdout))
            .ok_or_else(|| SealError::new(ErrorKind::Unavailable, "tpm2_readclock: output"))
    }

    /// The state of an NV counter (checked to have the counter attributes
    /// RoboDR defines; another kind of index is an error).
    pub fn counter(&self, index: u32) -> Result<Counter, SealError> {
        let Some(p) = self.nv_public(index)? else {
            return Ok(Counter::Undefined);
        };
        if p.size != 8 || (p.attributes & !(1 << 29)) != (COUNTER_NV_ATTRIBUTES & !(1 << 29)) {
            return Err(invalid(format!(
                "NV index {} is not a RoboDR counter (attributes 0x{:08x})",
                hx(index),
                p.attributes
            )));
        }
        if !p.written() {
            return Ok(Counter::Unwritten);
        }
        let o = self.must(
            "tpm2_nvread",
            &[hx(index), "-C".into(), hx(index), "-s".into(), "8".into()],
            None,
            ErrorKind::Unavailable,
            "read NV counter",
        )?;
        let a: [u8; 8] = o
            .stdout
            .as_slice()
            .try_into()
            .map_err(|_| SealError::new(ErrorKind::Unavailable, "tpm2_nvread: 8 bytes"))?;
        Ok(Counter::Value(u64::from_be_bytes(a)))
    }

    /// Define an anchor counter (owner authorization on stdin); left
    /// unwritten. Refused unless the owner and lockout authorizations are
    /// set (a counter root could undefine is no anchor).
    pub fn define_counter(&self, index: u32, owner_auth: &[u8]) -> Result<bool, SealError> {
        self.require_ownership()?;
        if self.counter(index)? != Counter::Undefined {
            return Ok(false);
        }
        let mut args = vec![
            hx(index),
            "-C".into(),
            "o".into(),
            "-s".into(),
            "8".into(),
            "-a".into(),
            COUNTER_NV_DEFINE.into(),
        ];
        args.extend(Self::owner_args());
        self.must(
            "tpm2_nvdefine",
            &args,
            Some(owner_auth),
            ErrorKind::Unavailable,
            "define NV counter",
        )?;
        Ok(true)
    }

    /// Increment an NV counter once.
    pub fn increment_counter(&self, index: u32) -> Result<(), SealError> {
        let i = hx(index);
        self.must(
            "tpm2_nvincrement",
            &[i.clone(), "-C".into(), i],
            None,
            ErrorKind::Unavailable,
            "increment NV counter",
        )
        .map(|_| ())
    }
}
