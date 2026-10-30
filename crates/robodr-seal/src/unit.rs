//! A unit's sealing state (the **seal directory**, `0700`, root-owned,
//! outside the runtime volume):
//!
//! ```text
//! unit.json      enrolment record (public: unit, platform, mode, UWK public,
//!                TPM handles, epoch, policy authority, UWK authPolicy)
//! uwk.pub        TPM mode: the UWK's public area (tpm2_create -u)
//! uwk.priv       TPM mode: the UWK's private blob, encrypted by the SRK
//! policy.json    TPM mode: the signed PCR policy in force
//! volume.wrap    TPM mode: the runtime-volume key wrapped to the UWK
//! erased.json    after crypto-erase: trigger and epochs
//! ```
//!
//! Nothing here is secret on its own: a disk image of the unit holds the
//! UWK only as a blob the unit's TPM alone can load and use, and only
//! under the policy. A unit **without a TPM** keeps its X25519 UWK in a
//! key file **inside the runtime volume** (`fallback_key`), which opens only
//! through the site's Tang server (§7.7).

use crate::keys;
use crate::policy::{self, CheckedPolicy};
use crate::tpm::{Tpm, WorkDir};
use crate::wrap::{self, Recipient, Unwrapper, WrapContext, X25519Secret};
use crate::{invalid, io_err, ErrorKind, SealError};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const UNIT_FORMAT: &str = "robodr-seal-unit/1";
pub const ERASED_FORMAT: &str = "robodr-seal-erased/1";
pub const UNIT_FILE: &str = "unit.json";
pub const UWK_PUB_FILE: &str = "uwk.pub";
pub const UWK_PRIV_FILE: &str = "uwk.priv";
pub const POLICY_FILE: &str = "policy.json";
pub const VOLUME_WRAP_FILE: &str = "volume.wrap";
pub const ERASED_FILE: &str = "erased.json";
const MAX_STATE_FILE: usize = 64 * 1024;

/// TPM or software fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Tpm,
    Fallback,
}

/// TPM part of the enrolment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmRecord {
    pub srk: String,
    pub epoch_nv: String,
    /// The erase epoch the UWK is bound to.
    pub epoch: u64,
    pub floor_nv: String,
    /// SEC1 public key of the policy authority (hex).
    pub policy_authority: String,
    /// Its TPM name (hex).
    pub policy_authority_name: String,
    /// The UWK's authPolicy (hex).
    pub auth_policy: String,
}

/// The enrolment record (`unit.json`); also what the depot needs to wrap
/// keys for the unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitRecord {
    pub format: String,
    pub unit: String,
    pub platform: String,
    pub mode: Mode,
    /// The UWK's public key (hex): SEC1 P-256 (TPM) or X25519 (fallback).
    pub uwk_public: String,
    pub tpm: Option<TpmRecord>,
    /// Fallback: the UWK key file, inside the runtime volume.
    pub fallback_key: Option<String>,
}

impl UnitRecord {
    /// Parse and check a record (also the depot's input).
    pub fn parse(bytes: &[u8]) -> Result<Self, SealError> {
        if bytes.len() > MAX_STATE_FILE {
            return Err(invalid("unit record too large"));
        }
        let r: UnitRecord =
            serde_json::from_slice(bytes).map_err(|e| invalid(format!("unit record: {e}")))?;
        if r.format != UNIT_FORMAT {
            return Err(invalid("unit record: unsupported format"));
        }
        if !robodr_pkg::common::is_label(&r.unit) || !robodr_pkg::common::is_label(&r.platform) {
            return Err(invalid("unit record: bad unit or platform"));
        }
        let ok = match r.mode {
            Mode::Tpm => r.tpm.is_some() && r.fallback_key.is_none(),
            Mode::Fallback => r.tpm.is_none() && r.fallback_key.is_some(),
        };
        if !ok {
            return Err(invalid("unit record: mode does not match its members"));
        }
        r.recipient()?;
        if let Some(t) = &r.tpm {
            for (s, top) in [(&t.srk, 0x81), (&t.epoch_nv, 0x01), (&t.floor_nv, 0x01)] {
                parse_handle(s, top)?;
            }
            keys::policy_verify_key(&t.policy_authority)?;
        }
        if let Some(k) = &r.fallback_key {
            if !Path::new(k).is_absolute() {
                return Err(invalid("unit record: fallback_key must be absolute"));
            }
        }
        Ok(r)
    }

    /// The UWK as a wrap recipient.
    pub fn recipient(&self) -> Result<Recipient, SealError> {
        let b = crate::from_hex(&self.uwk_public)
            .ok_or_else(|| invalid("unit record: bad uwk_public"))?;
        match self.mode {
            Mode::Tpm => Recipient::p256(&b),
            Mode::Fallback => {
                let a: [u8; 32] = b
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("unit record: X25519 key must be 32 bytes"))?;
                Ok(Recipient::X25519(a))
            }
        }
    }
}

/// What erase did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EraseReport {
    pub format: String,
    pub unit: String,
    pub trigger: String,
    pub mode: Mode,
    pub epoch_before: Option<u64>,
    pub epoch_after: Option<u64>,
    pub volume_header_erased: bool,
}

/// Status of a unit's sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub unit: String,
    pub mode: Mode,
    pub erased: bool,
    pub epoch_enrolled: Option<u64>,
    pub epoch_now: Option<u64>,
    pub policy_version: Option<u32>,
    pub floor_bits: Option<u64>,
}

fn ensure_dir(p: &Path) -> Result<(), SealError> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            if m.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(p, fs::Permissions::from_mode(0o700))
                    .map_err(|e| io_err(p, e))?;
            }
            Ok(())
        }
        Ok(_) => Err(invalid(format!("{}: not a directory", p.display()))),
        Err(_) => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)
            .map_err(|e| io_err(p, e)),
    }
}

/// Write `data` to `dir/name` atomically (`0600`, fsynced).
pub fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<(), SealError> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_err(&tmp, e))?;
    f.write_all(data).map_err(|e| io_err(&tmp, e))?;
    f.sync_all().map_err(|e| io_err(&tmp, e))?;
    let dst = dir.join(name);
    fs::rename(&tmp, &dst).map_err(|e| io_err(&dst, e))?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn read_small(p: &Path) -> Result<Vec<u8>, SealError> {
    let b = robodr_release_like_read(p, MAX_STATE_FILE)?;
    Ok(b)
}

/// Bounded read that refuses symlinks and non-regular files.
fn robodr_release_like_read(p: &Path, max: usize) -> Result<Vec<u8>, SealError> {
    use std::io::Read;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0o400000) // O_NOFOLLOW
        .open(p)
        .map_err(|e| io_err(p, e))?;
    let md = f.metadata().map_err(|e| io_err(p, e))?;
    if !md.is_file() {
        return Err(invalid(format!("{}: not a regular file", p.display())));
    }
    let mut b = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|e| io_err(p, e))?;
    if b.len() > max {
        return Err(invalid(format!("{}: too large", p.display())));
    }
    Ok(b)
}

/// A unit's sealing state, opened.
#[derive(Debug)]
pub struct Unit {
    dir: PathBuf,
    rec: UnitRecord,
    tpm: Option<Tpm>,
}

/// The UWK in the TPM, as a wrap recipient, under one signed policy.
struct TpmUnwrapper<'a> {
    unit: &'a Unit,
    tpm: &'a Tpm,
    policy: &'a CheckedPolicy,
    work: &'a WorkDir,
}

impl Unwrapper for TpmUnwrapper<'_> {
    fn recipient(&self) -> Recipient {
        // Checked when the record was opened.
        self.unit
            .rec
            .recipient()
            .unwrap_or(Recipient::X25519([0u8; 32]))
    }

    fn shared(&self, ephemeral: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
        let t = self.unit.tpm_record()?;
        let authority = hex65(&t.policy_authority)?;
        let name = crate::from_hex(&t.policy_authority_name)
            .ok_or_else(|| invalid("unit record: bad authority name"))?;
        let (pu, pr) = self.unit.uwk_blobs()?;
        self.tpm.ecdh(
            self.work,
            &pu,
            &pr,
            self.policy,
            &authority,
            &name,
            t.epoch,
            ephemeral,
        )
    }
}

fn hex65(s: &str) -> Result<[u8; 65], SealError> {
    let b = crate::from_hex(s).ok_or_else(|| invalid("bad hex"))?;
    b.as_slice()
        .try_into()
        .map_err(|_| invalid("expected 65 bytes"))
}

impl Unit {
    /// Enrol a unit with a TPM: create the UWK inside the TPM, bound to
    /// the policy authority's signed policies for `platform` and to the
    /// current erase epoch. The TPM must be provisioned
    /// ([`Tpm::provision`]).
    pub fn enroll_tpm(
        dir: &Path,
        unit: &str,
        platform: &str,
        authority: &[u8; 65],
        tpm: Tpm,
    ) -> Result<Self, SealError> {
        if !robodr_pkg::common::is_label(unit) || !robodr_pkg::common::is_label(platform) {
            return Err(invalid("bad unit or platform label"));
        }
        ensure_dir(dir)?;
        if fs::symlink_metadata(dir.join(UNIT_FILE)).is_ok() {
            return Err(invalid(format!(
                "{}: already enrolled (re-enrolment after erase: a new seal directory)",
                dir.display()
            )));
        }
        let epoch = tpm.epoch()?;
        let w = WorkDir::new(dir)?;
        let name = tpm.external_key_name(&w, authority)?;
        let auth = policy::uwk_auth_policy(&name, platform, tpm.cfg.epoch_nv, epoch);
        let (pu, pr, point) = tpm.create_uwk(&w, &auth)?;
        write_atomic(dir, UWK_PUB_FILE, &pu)?;
        write_atomic(dir, UWK_PRIV_FILE, &pr)?;
        let hx = |v: u32| format!("0x{v:08x}");
        let rec = UnitRecord {
            format: UNIT_FORMAT.into(),
            unit: unit.into(),
            platform: platform.into(),
            mode: Mode::Tpm,
            uwk_public: crate::to_hex(&point),
            tpm: Some(TpmRecord {
                srk: hx(tpm.cfg.srk),
                epoch_nv: hx(tpm.cfg.epoch_nv),
                epoch,
                floor_nv: hx(tpm.cfg.floor_nv),
                policy_authority: crate::to_hex(authority),
                policy_authority_name: crate::to_hex(&name),
                auth_policy: crate::to_hex(&auth),
            }),
            fallback_key: None,
        };
        let bytes = serde_json::to_vec(&rec).map_err(|e| invalid(e.to_string()))?;
        write_atomic(dir, UNIT_FILE, &bytes)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            rec,
            tpm: Some(tpm),
        })
    }

    /// Enrol a unit without a TPM: an X25519 UWK written to `key_path`,
    /// which must be inside the (open) runtime volume.
    pub fn enroll_fallback(
        dir: &Path,
        unit: &str,
        platform: &str,
        key_path: &Path,
    ) -> Result<Self, SealError> {
        if !robodr_pkg::common::is_label(unit) || !robodr_pkg::common::is_label(platform) {
            return Err(invalid("bad unit or platform label"));
        }
        if !key_path.is_absolute() {
            return Err(invalid("fallback key path must be absolute"));
        }
        ensure_dir(dir)?;
        if fs::symlink_metadata(dir.join(UNIT_FILE)).is_ok() {
            return Err(invalid(format!("{}: already enrolled", dir.display())));
        }
        if let Some(parent) = key_path.parent() {
            ensure_dir(parent)?;
        }
        let k = X25519Secret::generate()?;
        keys::x25519_write(key_path, &k)?;
        let rec = UnitRecord {
            format: UNIT_FORMAT.into(),
            unit: unit.into(),
            platform: platform.into(),
            mode: Mode::Fallback,
            uwk_public: crate::to_hex(&k.public()),
            tpm: None,
            fallback_key: Some(key_path.display().to_string()),
        };
        let bytes = serde_json::to_vec(&rec).map_err(|e| invalid(e.to_string()))?;
        write_atomic(dir, UNIT_FILE, &bytes)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            rec,
            tpm: None,
        })
    }

    /// Open an enrolled seal directory. A TPM unit needs `tpm` (whose
    /// handles must be the enrolled ones).
    pub fn open(dir: &Path, tpm: Option<Tpm>) -> Result<Self, SealError> {
        let rec = UnitRecord::parse(&read_small(&dir.join(UNIT_FILE))?)?;
        if rec.mode == Mode::Tpm {
            let t = rec.tpm.as_ref().ok_or_else(|| invalid("no TPM record"))?;
            let tpm = tpm.as_ref().ok_or_else(|| {
                SealError::new(
                    ErrorKind::Unavailable,
                    "this unit's keys are in a TPM; none configured",
                )
            })?;
            let hx = |v: u32| format!("0x{v:08x}");
            if t.srk != hx(tpm.cfg.srk)
                || t.epoch_nv != hx(tpm.cfg.epoch_nv)
                || t.floor_nv != hx(tpm.cfg.floor_nv)
            {
                return Err(invalid(
                    "the configured TPM handles are not the ones this unit was enrolled with",
                ));
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            rec,
            tpm,
        })
    }

    pub fn record(&self) -> &UnitRecord {
        &self.rec
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn tpm_record(&self) -> Result<&TpmRecord, SealError> {
        self.rec
            .tpm
            .as_ref()
            .ok_or_else(|| invalid("not a TPM unit"))
    }

    fn tpm(&self) -> Result<&Tpm, SealError> {
        self.tpm
            .as_ref()
            .ok_or_else(|| SealError::new(ErrorKind::Unavailable, "no TPM configured"))
    }

    fn uwk_blobs(&self) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let rd = |n: &str| {
            read_small(&self.dir.join(n)).map_err(|e| {
                if self.is_erased() {
                    SealError::new(ErrorKind::Erased, "the unit's keys were crypto-erased")
                } else {
                    e
                }
            })
        };
        Ok((rd(UWK_PUB_FILE)?, rd(UWK_PRIV_FILE)?))
    }

    /// Whether erase ran on this seal directory.
    pub fn is_erased(&self) -> bool {
        fs::symlink_metadata(self.dir.join(ERASED_FILE)).is_ok()
    }

    /// The signed policy in force (TPM units).
    pub fn policy(&self) -> Result<CheckedPolicy, SealError> {
        let t = self.tpm_record()?;
        let b = read_small(&self.dir.join(POLICY_FILE)).map_err(|e| {
            SealError::new(
                ErrorKind::PolicyRefused,
                format!("no signed policy installed: {e}"),
            )
        })?;
        policy::verify(
            &b,
            &hex65(&t.policy_authority)?,
            &self.rec.platform,
            parse_handle(&t.floor_nv, 0x01)?,
        )
    }

    /// Install a signed policy (verified against the enrolled authority,
    /// platform and floor index; a version the TPM already revoked is
    /// refused). The previous one is replaced; revoking it is
    /// [`Unit::commit_policy`], after this one has unsealed.
    pub fn install_policy(&self, bytes: &[u8]) -> Result<CheckedPolicy, SealError> {
        let t = self.tpm_record()?;
        let p = policy::verify(
            bytes,
            &hex65(&t.policy_authority)?,
            &self.rec.platform,
            parse_handle(&t.floor_nv, 0x01)?,
        )?;
        let bits = self.tpm()?.floor_bits()?;
        if bits & u64::from_be_bytes(policy::version_mask(p.doc.version)) != 0 {
            return Err(SealError::new(
                ErrorKind::PolicyRefused,
                format!(
                    "signed policy version {} was revoked on this unit (policy floor)",
                    p.doc.version
                ),
            ));
        }
        write_atomic(&self.dir, POLICY_FILE, bytes)?;
        Ok(p)
    }

    /// Prove the unit can unseal now: wrap a random key to its own UWK
    /// and unwrap it (the full TPM policy, for TPM units).
    pub fn probe(&self) -> Result<(), SealError> {
        let ctx = WrapContext::Probe {
            unit: self.rec.unit.clone(),
        };
        let k = crate::random32()?;
        let w = wrap::wrap(&self.rec.recipient()?, &k, &ctx)?;
        let back = self.unwrap(&w, &ctx)?;
        if crate::ct_eq(&back[..], &k[..]) {
            Ok(())
        } else {
            Err(crate::unauthentic("probe key came back different"))
        }
    }

    /// Revoke, in the TPM, every policy version below the one in force,
    /// but only after the policy in force has unsealed on this boot
    /// ([`Unit::probe`]): a policy that does not match this boot never
    /// revokes the one that does.
    pub fn commit_policy(&self) -> Result<u32, SealError> {
        let p = self.policy()?;
        self.probe()?;
        self.tpm()?.revoke_below(p.doc.version)?;
        Ok(p.doc.version)
    }

    fn check_not_erased(&self) -> Result<(), SealError> {
        if self.is_erased() {
            return Err(SealError::new(
                ErrorKind::Erased,
                "the unit's keys were crypto-erased",
            ));
        }
        if let (Some(t), Some(tpm)) = (&self.rec.tpm, &self.tpm) {
            let now = tpm.epoch()?;
            if now != t.epoch {
                return Err(SealError::new(
                    ErrorKind::Erased,
                    format!(
                        "erase epoch is {now}, the UWK was bound to {}: crypto-erased",
                        t.epoch
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Unwrap a 32-byte key wrapped to this unit for `ctx`.
    pub fn unwrap(&self, w: &[u8], ctx: &WrapContext) -> Result<Zeroizing<[u8; 32]>, SealError> {
        // Algorithm and length first: no TPM round trip for a wrap that
        // cannot be this unit's.
        let p = wrap::parse(w)?;
        if p.alg != self.rec.recipient()?.alg() {
            return Err(crate::unauthentic(
                "wrap is for another kind of recipient key",
            ));
        }
        self.check_not_erased()?;
        match self.rec.mode {
            Mode::Tpm => {
                let pol = self.policy()?;
                let work = WorkDir::new(&self.dir)?;
                let u = TpmUnwrapper {
                    unit: self,
                    tpm: self.tpm()?,
                    policy: &pol,
                    work: &work,
                };
                wrap::unwrap(&u, w, ctx)
            }
            Mode::Fallback => {
                let path = self
                    .rec
                    .fallback_key
                    .as_deref()
                    .ok_or_else(|| invalid("no fallback key"))?;
                let k = keys::x25519_load(Path::new(path)).map_err(|e| {
                    SealError::new(
                        ErrorKind::Unavailable,
                        format!("the UWK is on the runtime volume, which is not open: {e}"),
                    )
                })?;
                if k.public().as_slice() != self.rec.recipient()?.public_bytes() {
                    return Err(invalid("the fallback key file is not the enrolled UWK"));
                }
                wrap::unwrap(&k, w, ctx)
            }
        }
    }

    /// Unwrap the content key of sealed RPK `rpk_digest` from its wrap for
    /// this unit, and check it against the manifest's key commitment.
    pub fn unwrap_content_key(
        &self,
        w: &[u8],
        rpk_digest: &str,
        seal: &robodr_pkg::rpk::Seal,
    ) -> Result<crate::chunk::ContentKey, SealError> {
        let k = self.unwrap(
            w,
            &WrapContext::Unit {
                unit: self.rec.unit.clone(),
                rpk_digest: rpk_digest.into(),
            },
        )?;
        let ck = crate::chunk::ContentKey::from_bytes(&k[..])?;
        let sid = seal_id(seal)?;
        let commit = crate::from_hex(&seal.ck_commit).ok_or_else(|| invalid("bad ck_commit"))?;
        ck.check_commit(&sid, &commit)?;
        Ok(ck)
    }

    /// Create the runtime-volume key: random, stored only wrapped to the
    /// UWK (`volume.wrap`). TPM units only (a fallback volume is bound to
    /// Tang instead). Returns the key for `luksFormat`.
    pub fn create_volume_key(&self) -> Result<Zeroizing<[u8; 32]>, SealError> {
        if self.rec.mode != Mode::Tpm {
            return Err(invalid(
                "a unit without a TPM binds its volume to Tang, not to a stored wrap",
            ));
        }
        if fs::symlink_metadata(self.dir.join(VOLUME_WRAP_FILE)).is_ok() {
            return Err(invalid("a volume key exists already"));
        }
        let k = crate::random32()?;
        let w = wrap::wrap(
            &self.rec.recipient()?,
            &k,
            &WrapContext::Volume {
                unit: self.rec.unit.clone(),
            },
        )?;
        write_atomic(&self.dir, VOLUME_WRAP_FILE, &w)?;
        Ok(k)
    }

    /// The runtime-volume key (TPM policy enforced).
    pub fn volume_key(&self) -> Result<Zeroizing<[u8; 32]>, SealError> {
        self.check_not_erased()?;
        let w = read_small(&self.dir.join(VOLUME_WRAP_FILE))?;
        self.unwrap(
            &w,
            &WrapContext::Volume {
                unit: self.rec.unit.clone(),
            },
        )
    }

    /// Crypto-erase (§7.6, §7.7). TPM: increment the erase epoch (every key
    /// sealed under the old one is dead in the TPM), then remove the UWK
    /// blobs and the volume wrap. Fallback: overwrite and delete the UWK
    /// file. With `volume`, also wipe every keyslot of the LUKS2 header
    /// (`cryptsetup erase`), which defeats a later Tang recovery too. The
    /// erase is reported only once the epoch moved (TPM) or the key file
    /// is gone (fallback).
    pub fn erase(
        &self,
        trigger: &str,
        volume: Option<(&crate::luks::Luks, &Path)>,
    ) -> Result<EraseReport, SealError> {
        if trigger.is_empty()
            || trigger.len() > 64
            || !trigger
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid("trigger must be [a-z0-9_]{1,64}"));
        }
        let mut rep = EraseReport {
            format: ERASED_FORMAT.into(),
            unit: self.rec.unit.clone(),
            trigger: trigger.into(),
            mode: self.rec.mode,
            epoch_before: None,
            epoch_after: None,
            volume_header_erased: false,
        };
        match self.rec.mode {
            Mode::Tpm => {
                let tpm = self.tpm()?;
                let before = tpm.epoch()?;
                let after = tpm.increment_epoch()?;
                if after <= before {
                    return Err(SealError::new(
                        ErrorKind::Unavailable,
                        "the erase epoch did not move",
                    ));
                }
                rep.epoch_before = Some(before);
                rep.epoch_after = Some(after);
                for f in [UWK_PRIV_FILE, UWK_PUB_FILE, VOLUME_WRAP_FILE] {
                    let _ = fs::remove_file(self.dir.join(f));
                }
            }
            Mode::Fallback => {
                if let Some(p) = &self.rec.fallback_key {
                    let p = Path::new(p);
                    if let Ok(md) = fs::symlink_metadata(p) {
                        if md.is_file() {
                            if let Ok(mut f) = OpenOptions::new().write(true).open(p) {
                                let _ = f.write_all(&vec![0u8; md.len() as usize]);
                                let _ = f.sync_all();
                            }
                        }
                        fs::remove_file(p).map_err(|e| io_err(p, e))?;
                    }
                }
            }
        }
        if let Some((luks, dev)) = volume {
            luks.erase(dev)?;
            rep.volume_header_erased = true;
        }
        let bytes = serde_json::to_vec(&rep).map_err(|e| invalid(e.to_string()))?;
        write_atomic(&self.dir, ERASED_FILE, &bytes)?;
        Ok(rep)
    }

    /// Status (reads the TPM for TPM units).
    pub fn status(&self) -> Status {
        let tpm_rec = self.rec.tpm.as_ref();
        let tpm = self.tpm.as_ref();
        Status {
            unit: self.rec.unit.clone(),
            mode: self.rec.mode,
            erased: self.is_erased(),
            epoch_enrolled: tpm_rec.map(|t| t.epoch),
            epoch_now: tpm.and_then(|t| t.epoch().ok()),
            policy_version: self.policy().ok().map(|p| p.doc.version),
            floor_bits: tpm.and_then(|t| t.floor_bits().ok()),
        }
    }
}

/// `0x` + 8 lower-case hex digits whose top byte is `top`.
pub fn parse_handle(s: &str, top: u32) -> Result<u32, SealError> {
    s.strip_prefix("0x")
        .filter(|h| h.len() == 8 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .filter(|v| v >> 24 == top)
        .ok_or_else(|| invalid(format!("bad TPM handle {:?}", robodr_pkg::common::trunc(s))))
}

/// The `seal_id` of a manifest's seal member.
pub fn seal_id(seal: &robodr_pkg::rpk::Seal) -> Result<[u8; 32], SealError> {
    let b = crate::from_hex(&seal.seal_id).ok_or_else(|| invalid("bad seal_id"))?;
    b.as_slice()
        .try_into()
        .map_err(|_| invalid("seal_id must be 32 bytes"))
}
