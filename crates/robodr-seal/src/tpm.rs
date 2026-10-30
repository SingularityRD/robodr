//! The unit's TPM, driven through `tpm2-tools` (the approach of
//! `robodr-blackbox`'s `TpmNvCounterAnchor`: fixed tool names from a fixed
//! directory, cleared environment plus `TPM2TOOLS_TCTI`, bounded time).
//!
//! What lives in the TPM:
//!
//! * the storage root key **SRK** (ECC P-256, the owner hierarchy's default
//!   storage template), persistent at [`TpmConfig::srk`] (default
//!   `0x81000001`): the parent of the UWK and the salt key of every policy
//!   session;
//! * the **erase-epoch** counter and the **policy-floor** bit field
//!   ([`crate::policy`]);
//! * the **UWK** itself is a P-256 ECDH key created *inside* the TPM
//!   (`sensitivedataorigin`, `fixedtpm`, `fixedparent`, no `userwithauth`,
//!   authPolicy [`crate::policy::uwk_auth_policy`]). Only its public part
//!   and its private blob, encrypted by the SRK, are on disk; the blob is
//!   useless without this TPM.
//!
//! Unwrapping (`TPM2_ECDH_ZGen`) runs in a **salted policy session with
//! parameter encryption** (bound to the SRK), so the shared secret `Z` does
//! not cross the TPM bus in clear (§7.8, T7 mitigation against passive
//! sniffing; an active interposer is not claimed). `Z` is written to the
//! tool's stdout (a pipe), never to a file. The policy steps are:
//!
//! 1. `TPM2_VerifySignature` of the signed policy by the policy authority's
//!    key (loaded as an external key; its TPM name must be the one recorded
//!    at enrolment) → a ticket;
//! 2. `TPM2_PolicyPCR` (the TPM reads its own PCRs);
//! 3. `TPM2_PolicyNV` floor: the policy's version bit is clear;
//! 4. `TPM2_PolicyAuthorize` with the ticket: refused unless the digest so
//!    far is exactly the signed approved policy (a changed PCR fails here);
//! 5. `TPM2_PolicyNV` epoch `==` the UWK's epoch (fails once erased);
//! 6. `TPM2_ECDH_ZGen` with the UWK under that session.
//!
//! Without a resource manager (a bare swtpm socket) every loaded object
//! stays loaded after a tool exits, so each step is followed by
//! `tpm2_flushcontext -t`; with the kernel's `/dev/tpmrm0` that is a no-op.

use crate::cmd::{tool, Output, Runner};
use crate::policy::{self, CheckedPolicy};
use crate::{invalid, io_err, ErrorKind, SealError};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// Default persistent handle of the SRK (the TCG-recommended one).
pub const DEFAULT_SRK: u32 = 0x8100_0001;
/// Default erase-epoch counter index (owner NV range, next to the black
/// box's `0x01500020`).
pub const DEFAULT_EPOCH_NV: u32 = 0x0150_0040;
/// Default policy-floor bit-field index.
pub const DEFAULT_FLOOR_NV: u32 = 0x0150_0041;
/// Default TCTI.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";
/// Default tools directory.
pub const DEFAULT_TOOLS_DIR: &str = "/usr/bin";
/// Default bound on one tool run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// `tpm2_create -a` of the UWK.
pub const UWK_ATTRIBUTES: &str = "fixedtpm|fixedparent|sensitivedataorigin|decrypt|noda";

/// Where the TPM is and which handles RoboDR uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmConfig {
    pub tools_dir: PathBuf,
    pub tcti: String,
    pub timeout: Duration,
    pub srk: u32,
    pub epoch_nv: u32,
    pub floor_nv: u32,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            tools_dir: PathBuf::from(DEFAULT_TOOLS_DIR),
            tcti: DEFAULT_TCTI.into(),
            timeout: DEFAULT_TIMEOUT,
            srk: DEFAULT_SRK,
            epoch_nv: DEFAULT_EPOCH_NV,
            floor_nv: DEFAULT_FLOOR_NV,
        }
    }
}

impl TpmConfig {
    pub fn validate(&self) -> Result<(), SealError> {
        if !self.tools_dir.is_absolute() {
            return Err(invalid("tpm tools_dir must be absolute"));
        }
        if self.tcti.is_empty() || self.tcti.len() > 512 || self.tcti.chars().any(char::is_control)
        {
            return Err(invalid("TCTI must be 1..=512 printable characters"));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(120) {
            return Err(invalid("tpm timeout must be in (0, 120 s]"));
        }
        if self.srk >> 24 != 0x81 {
            return Err(invalid("srk must be a persistent handle 0x81xxxxxx"));
        }
        for i in [self.epoch_nv, self.floor_nv] {
            if i >> 24 != 0x01 {
                return Err(invalid("NV indices must be 0x01xxxxxx"));
            }
        }
        if self.epoch_nv == self.floor_nv {
            return Err(invalid("epoch and floor NV indices must differ"));
        }
        Ok(())
    }
}

fn hx(v: u32) -> String {
    format!("0x{v:08x}")
}

/// A private working directory (contexts, policy files, the ephemeral
/// point; never a secret): created `0700`, removed on drop.
pub struct WorkDir(PathBuf);

impl WorkDir {
    pub fn new(parent: &Path) -> Result<Self, SealError> {
        let mut nonce = [0u8; 8];
        robodr_blackbox::crypto::fill_random(&mut nonce).map_err(|e| io_err(parent, e))?;
        let p = parent.join(format!(".work-{}", crate::to_hex(&nonce)));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .map_err(|e| io_err(&p, e))?;
        Ok(Self(p))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn write(&self, name: &str, data: &[u8]) -> Result<String, SealError> {
        let p = self.path(name);
        fs::write(&p, data).map_err(|e| io_err(&p, e))?;
        Ok(p.display().to_string())
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The TPM.
#[derive(Debug)]
pub struct Tpm {
    pub cfg: TpmConfig,
    runner: Box<dyn Runner>,
}

/// A created UWK: public blob, private blob (encrypted by the SRK), SEC1
/// public point.
pub type UwkBlobs = (Vec<u8>, Vec<u8>, [u8; 65]);

/// What [`Tpm::provision`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provisioned {
    pub defined_epoch: bool,
    pub defined_floor: bool,
    pub created_srk: bool,
}

/// TPM2B_ECC_POINT of a SEC1 uncompressed P-256 point.
pub fn ecc_point(sec1: &[u8]) -> Result<Vec<u8>, SealError> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(invalid("not an uncompressed P-256 point"));
    }
    let mut b = Vec::with_capacity(70);
    b.extend_from_slice(&68u16.to_be_bytes());
    b.extend_from_slice(&32u16.to_be_bytes());
    b.extend_from_slice(&sec1[1..33]);
    b.extend_from_slice(&32u16.to_be_bytes());
    b.extend_from_slice(&sec1[33..]);
    Ok(b)
}

/// The x-coordinate of a TPM2B_ECC_POINT (`tpm2_ecdhzgen -o`).
pub fn ecc_point_x(b: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
    if b.len() != 70 || b[..4] != [0, 68, 0, 32] || b[36..38] != [0, 32] {
        return Err(SealError::new(
            ErrorKind::Unavailable,
            "tpm2_ecdhzgen: unexpected output",
        ));
    }
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(&b[4..36]);
    Ok(z)
}

impl Tpm {
    pub fn new(cfg: TpmConfig, runner: Box<dyn Runner>) -> Result<Self, SealError> {
        cfg.validate()?;
        Ok(Self { cfg, runner })
    }

    /// Run a tool; `Ok` with the output whether or not it succeeded.
    pub fn run(
        &self,
        name: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<Output, SealError> {
        let p = tool(&self.cfg.tools_dir, name)?;
        self.runner.run(
            &p,
            args,
            &[("TPM2TOOLS_TCTI", self.cfg.tcti.as_str())],
            stdin,
            self.cfg.timeout,
        )
    }

    fn flush(&self) {
        let _ = self.run("tpm2_flushcontext", &["-t".into()], None);
    }

    fn flush_sessions(&self) {
        let _ = self.run("tpm2_flushcontext", &["-l".into()], None);
    }

    /// Run a tool that must succeed; a failure is `kind` with its error.
    fn must(
        &self,
        name: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        kind: ErrorKind,
        what: &str,
    ) -> Result<Output, SealError> {
        let o = self.run(name, args, stdin)?;
        self.flush();
        if o.ok() {
            Ok(o)
        } else {
            Err(SealError::new(
                kind,
                format!("{what}: {name} failed: {}", o.error_line()),
            ))
        }
    }

    fn nv_public(
        &self,
        index: u32,
    ) -> Result<Option<robodr_blackbox::tpm_anchor::NvPublic>, SealError> {
        let o = self.run("tpm2_nvreadpublic", &[hx(index)], None)?;
        if !o.ok() {
            return Ok(None);
        }
        robodr_blackbox::tpm_anchor::parse_nvreadpublic(&o.stdout, index)
            .map(Some)
            .map_err(|e| SealError::new(ErrorKind::Unavailable, e))
    }

    fn owner_args(owner_auth: Option<&[u8]>) -> Vec<String> {
        if owner_auth.is_some() {
            vec!["-P".into(), "file:-".into()]
        } else {
            vec![]
        }
    }

    /// Define (once) the erase-epoch counter, the policy-floor bit field
    /// and the persistent SRK. Idempotent; an index that exists with other
    /// attributes is an error, never redefined. `owner_auth` is the owner
    /// hierarchy's authorization if one is set (it should be, so nobody on
    /// the unit can undefine the floor; `docs/OPERATIONS.md`).
    pub fn provision(&self, owner_auth: Option<&[u8]>) -> Result<Provisioned, SealError> {
        let mut p = Provisioned::default();
        for (index, define, attrs, is_epoch) in [
            (
                self.cfg.epoch_nv,
                policy::EPOCH_NV_DEFINE,
                policy::EPOCH_NV_ATTRIBUTES,
                true,
            ),
            (
                self.cfg.floor_nv,
                policy::FLOOR_NV_DEFINE,
                policy::FLOOR_NV_ATTRIBUTES,
                false,
            ),
        ] {
            let mut public = self.nv_public(index)?;
            if public.is_none() {
                let mut args = vec![
                    hx(index),
                    "-C".into(),
                    "o".into(),
                    "-s".into(),
                    "8".into(),
                    "-a".into(),
                    define.into(),
                ];
                args.extend(Self::owner_args(owner_auth));
                self.must(
                    "tpm2_nvdefine",
                    &args,
                    owner_auth,
                    ErrorKind::Unavailable,
                    "provision",
                )?;
                if is_epoch {
                    p.defined_epoch = true;
                } else {
                    p.defined_floor = true;
                }
                public = self.nv_public(index)?;
            }
            let public = public.ok_or_else(|| {
                SealError::new(
                    ErrorKind::Unavailable,
                    format!("{}: not defined", hx(index)),
                )
            })?;
            if public.size != 8 || (public.attributes & !(1 << 29)) != (attrs & !(1 << 29)) {
                return Err(invalid(format!(
                    "NV index {} exists with other attributes (0x{:08x}, size {}); refusing to use \
                     or redefine it",
                    hx(index),
                    public.attributes,
                    public.size
                )));
            }
            if !public.written() {
                if is_epoch {
                    self.must(
                        "tpm2_nvincrement",
                        &[hx(index), "-C".into(), hx(index)],
                        None,
                        ErrorKind::Unavailable,
                        "provision",
                    )?;
                } else {
                    self.must(
                        "tpm2_nvsetbits",
                        &[hx(index), "-C".into(), hx(index), "-i".into(), "0".into()],
                        None,
                        ErrorKind::Unavailable,
                        "provision",
                    )?;
                }
            }
        }
        let srk = self.run("tpm2_readpublic", &["-c".into(), hx(self.cfg.srk)], None)?;
        self.flush();
        if !srk.ok() {
            let w = WorkDir::new(&std::env::temp_dir())?;
            let ctx = w.path("srk.ctx").display().to_string();
            let mut args = vec![
                "-C".into(),
                "o".into(),
                "-g".into(),
                "sha256".into(),
                "-G".into(),
                "ecc256".into(),
                "-c".into(),
                ctx.clone(),
            ];
            args.extend(Self::owner_args(owner_auth));
            self.must(
                "tpm2_createprimary",
                &args,
                owner_auth,
                ErrorKind::Unavailable,
                "provision SRK",
            )?;
            let mut args = vec!["-C".into(), "o".into(), "-c".into(), ctx, hx(self.cfg.srk)];
            args.extend(Self::owner_args(owner_auth));
            self.must(
                "tpm2_evictcontrol",
                &args,
                owner_auth,
                ErrorKind::Unavailable,
                "persist SRK",
            )?;
            p.created_srk = true;
        }
        Ok(p)
    }

    fn read_nv8(&self, index: u32) -> Result<[u8; 8], SealError> {
        let o = self.must(
            "tpm2_nvread",
            &[hx(index), "-C".into(), hx(index), "-s".into(), "8".into()],
            None,
            ErrorKind::Unavailable,
            "read NV",
        )?;
        o.stdout.as_slice().try_into().map_err(|_| {
            SealError::new(
                ErrorKind::Unavailable,
                format!("tpm2_nvread {}: expected 8 bytes", hx(index)),
            )
        })
    }

    /// The erase epoch.
    pub fn epoch(&self) -> Result<u64, SealError> {
        Ok(u64::from_be_bytes(self.read_nv8(self.cfg.epoch_nv)?))
    }

    /// The policy-floor bits.
    pub fn floor_bits(&self) -> Result<u64, SealError> {
        Ok(u64::from_be_bytes(self.read_nv8(self.cfg.floor_nv)?))
    }

    /// Crypto-erase: increment the erase-epoch counter once. Every key
    /// whose policy names the previous value is dead from now on.
    pub fn increment_epoch(&self) -> Result<u64, SealError> {
        let i = hx(self.cfg.epoch_nv);
        self.must(
            "tpm2_nvincrement",
            &[i.clone(), "-C".into(), i],
            None,
            ErrorKind::Unavailable,
            "erase",
        )?;
        self.epoch()
    }

    /// Revoke every signed policy version below `version` (set floor bits
    /// `0..version`). Bits are never cleared.
    pub fn revoke_below(&self, version: u32) -> Result<(), SealError> {
        if version == 0 {
            return Ok(());
        }
        let mask = u64::from_be_bytes(policy::revoke_below_mask(version));
        let i = hx(self.cfg.floor_nv);
        self.must(
            "tpm2_nvsetbits",
            &[
                i.clone(),
                "-C".into(),
                i,
                "-i".into(),
                format!("0x{mask:x}"),
            ],
            None,
            ErrorKind::Unavailable,
            "revoke policies",
        )?;
        Ok(())
    }

    /// The TPM name of the policy authority's public key (as
    /// `TPM2_LoadExternal` computes it).
    pub fn external_key_name(
        &self,
        w: &WorkDir,
        authority: &[u8; 65],
    ) -> Result<Vec<u8>, SealError> {
        let pem = w.write("authority.pem", crate::keys::p256_pem(authority).as_bytes())?;
        let ctx = w.path("authority.ctx").display().to_string();
        let name = w.path("authority.name");
        self.must(
            "tpm2_loadexternal",
            &[
                "-C".into(),
                "o".into(),
                "-G".into(),
                "ecc".into(),
                "-u".into(),
                pem,
                "-c".into(),
                ctx,
                "-n".into(),
                name.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "load policy authority key",
        )?;
        let n = fs::read(&name).map_err(|e| io_err(&name, e))?;
        if n.len() != 34 || n[..2] != [0x00, 0x0b] {
            return Err(SealError::new(
                ErrorKind::Unavailable,
                "unexpected TPM name of the policy authority key",
            ));
        }
        Ok(n)
    }

    /// Create the UWK under the SRK with `auth_policy`; returns the public
    /// and private blobs (as `tpm2_create -u / -r` write them) and the
    /// SEC1 public point.
    pub fn create_uwk(&self, w: &WorkDir, auth_policy: &[u8; 32]) -> Result<UwkBlobs, SealError> {
        let pol = w.write("uwk.policy", auth_policy)?;
        let (pu, pr) = (w.path("uwk.pub"), w.path("uwk.priv"));
        self.must(
            "tpm2_create",
            &[
                "-C".into(),
                hx(self.cfg.srk),
                "-G".into(),
                "ecc256:ecdh".into(),
                "-a".into(),
                UWK_ATTRIBUTES.into(),
                "-L".into(),
                pol,
                "-u".into(),
                pu.display().to_string(),
                "-r".into(),
                pr.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "create UWK",
        )?;
        let pub_blob = fs::read(&pu).map_err(|e| io_err(&pu, e))?;
        let priv_blob = fs::read(&pr).map_err(|e| io_err(&pr, e))?;
        let point = self.uwk_public(w, &pub_blob, &priv_blob)?;
        Ok((pub_blob, priv_blob, point))
    }

    fn load_uwk(
        &self,
        w: &WorkDir,
        pub_blob: &[u8],
        priv_blob: &[u8],
    ) -> Result<String, SealError> {
        let pu = w.write("load.pub", pub_blob)?;
        let pr = w.write("load.priv", priv_blob)?;
        let ctx = w.path("uwk.ctx").display().to_string();
        self.must(
            "tpm2_load",
            &[
                "-C".into(),
                hx(self.cfg.srk),
                "-u".into(),
                pu,
                "-r".into(),
                pr,
                "-c".into(),
                ctx.clone(),
            ],
            None,
            ErrorKind::Unavailable,
            "load UWK (another TPM, or the SRK changed)",
        )?;
        Ok(ctx)
    }

    /// The SEC1 public point of a UWK (loaded from its blobs).
    pub fn uwk_public(
        &self,
        w: &WorkDir,
        pub_blob: &[u8],
        priv_blob: &[u8],
    ) -> Result<[u8; 65], SealError> {
        let ctx = self.load_uwk(w, pub_blob, priv_blob)?;
        let der = w.path("uwk.der");
        self.must(
            "tpm2_readpublic",
            &[
                "-c".into(),
                ctx,
                "-f".into(),
                "der".into(),
                "-o".into(),
                der.display().to_string(),
            ],
            None,
            ErrorKind::Unavailable,
            "read UWK public",
        )?;
        let d = fs::read(&der).map_err(|e| io_err(&der, e))?;
        crate::keys::p256_from_spki_der(&d)
    }

    /// `Z` (x-coordinate) of the UWK with `ephemeral`, under the signed
    /// policy `pol`, the authority whose TPM name is `authority_name`, and
    /// erase epoch `epoch`. Any policy step the TPM refuses is
    /// [`ErrorKind::PolicyRefused`] (or [`ErrorKind::Erased`] for the
    /// epoch).
    #[allow(clippy::too_many_arguments)]
    pub fn ecdh(
        &self,
        w: &WorkDir,
        pub_blob: &[u8],
        priv_blob: &[u8],
        pol: &CheckedPolicy,
        authority: &[u8; 65],
        authority_name: &[u8],
        epoch: u64,
        ephemeral: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, SealError> {
        let r = self.ecdh_inner(
            w,
            pub_blob,
            priv_blob,
            pol,
            authority,
            authority_name,
            epoch,
            ephemeral,
        );
        self.flush();
        self.flush_sessions();
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn ecdh_inner(
        &self,
        w: &WorkDir,
        pub_blob: &[u8],
        priv_blob: &[u8],
        pol: &CheckedPolicy,
        authority: &[u8; 65],
        authority_name: &[u8],
        epoch: u64,
        ephemeral: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, SealError> {
        let refused = ErrorKind::PolicyRefused;
        let point = w.write("ephemeral.point", &ecc_point(ephemeral)?)?;
        let uwk = self.load_uwk(w, pub_blob, priv_blob)?;
        let name = self.external_key_name(w, authority)?;
        if !crate::ct_eq(&name, authority_name) {
            return Err(SealError::new(
                refused,
                "the policy authority key's TPM name differs from enrolment",
            ));
        }
        let ahash = w.write("ahash", &pol.digest())?;
        let sig = w.write("policy.sig", &pol.signature)?;
        let ticket = w.path("ticket").display().to_string();
        self.must(
            "tpm2_verifysignature",
            &[
                "-c".into(),
                w.path("authority.ctx").display().to_string(),
                "-d".into(),
                ahash,
                "-s".into(),
                sig,
                "-f".into(),
                "ecdsa".into(),
                "-t".into(),
                ticket.clone(),
            ],
            None,
            refused,
            "signed policy (not the policy authority's signature)",
        )?;
        let s = w.path("session.ctx").display().to_string();
        self.must(
            "tpm2_startauthsession",
            &[
                "--policy-session".into(),
                "-S".into(),
                s.clone(),
                "-c".into(),
                hx(self.cfg.srk),
            ],
            None,
            ErrorKind::Unavailable,
            "policy session",
        )?;
        self.must(
            "tpm2_sessionconfig",
            &[s.clone(), "--enable-encrypt".into()],
            None,
            ErrorKind::Unavailable,
            "session encryption",
        )?;
        self.must(
            "tpm2_policypcr",
            &["-S".into(), s.clone(), "-l".into(), pol.pcr_list()],
            None,
            ErrorKind::Unavailable,
            "PolicyPCR",
        )?;
        let mask = w.write("floor.mask", &policy::version_mask(pol.doc.version))?;
        self.must(
            "tpm2_policynv",
            &[
                "-S".into(),
                s.clone(),
                "-i".into(),
                mask,
                hx(self.cfg.floor_nv),
                "bc".into(),
            ],
            None,
            refused,
            &format!(
                "signed policy version {} is revoked (policy floor)",
                pol.doc.version
            ),
        )?;
        let approved = w.write("approved.policy", &pol.approved)?;
        let pref = w.write("policy.ref", &pol.policy_ref)?;
        self.must(
            "tpm2_policyauthorize",
            &[
                "-S".into(),
                s.clone(),
                "-i".into(),
                approved,
                "-q".into(),
                pref,
                "-n".into(),
                w.path("authority.name").display().to_string(),
                "-t".into(),
                ticket,
            ],
            None,
            refused,
            "boot measurements (PCRs) do not match the signed policy",
        )?;
        let e = w.write("epoch", &epoch.to_be_bytes())?;
        self.must(
            "tpm2_policynv",
            &[
                "-S".into(),
                s.clone(),
                "-i".into(),
                e,
                hx(self.cfg.epoch_nv),
                "eq".into(),
            ],
            None,
            ErrorKind::Erased,
            "erase epoch moved on: the unit's keys were crypto-erased",
        )?;
        let o = self.must(
            "tpm2_ecdhzgen",
            &[
                "-c".into(),
                uwk,
                "-p".into(),
                format!("session:{s}"),
                "-u".into(),
                point,
                "-o".into(),
                "/dev/stdout".into(),
            ],
            None,
            refused,
            "ECDH with the UWK",
        )?;
        ecc_point_x(&o.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_and_points() {
        TpmConfig::default().validate().unwrap();
        for f in [
            |c: &mut TpmConfig| c.tools_dir = "usr/bin".into(),
            |c: &mut TpmConfig| c.tcti = "a\nb".into(),
            |c: &mut TpmConfig| c.srk = 0x0150_0000,
            |c: &mut TpmConfig| c.epoch_nv = 0x8100_0000,
            |c: &mut TpmConfig| c.floor_nv = c.epoch_nv,
            |c: &mut TpmConfig| c.timeout = Duration::ZERO,
        ] {
            let mut c = TpmConfig::default();
            f(&mut c);
            assert!(c.validate().is_err(), "{c:?}");
        }
        let k = crate::wrap::p256_random().unwrap();
        let p = crate::wrap::p256_public_bytes(&k.public_key());
        let b = ecc_point(&p).unwrap();
        assert_eq!(b.len(), 70);
        assert_eq!(&ecc_point_x(&b).unwrap()[..], &p[1..33]);
        assert!(ecc_point_x(&b[..69]).is_err());
        assert!(ecc_point(&p[..64]).is_err());
    }
}
