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
use crate::luks::Luks;
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
/// Sprint 14a: the AK (under the EK) and the unit identity key (under the
/// SRK), TPM blobs.
pub const AK_PUB_FILE: &str = "ak.pub";
pub const AK_PRIV_FILE: &str = "ak.priv";
pub const UIK_PUB_FILE: &str = "uik.pub";
pub const UIK_PRIV_FILE: &str = "uik.priv";
/// Sprint 14a: a unit without a TPM keeps its identity key next to its
/// fallback UWK (inside the runtime volume).
pub const FALLBACK_UIK_FILE: &str = "uik.key";
/// Sprint 14b: the site lease in force.
pub const LEASE_FILE: &str = "lease.json";
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
    /// Sprint 14b: the depot lease key (SEC1 P-256, hex) a lease-gated UWK
    /// is bound to ([`crate::lease`]); absent for a UWK without a lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_key: Option<String>,
    /// Its TPM name (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_key_name: Option<String>,
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
            match (&t.lease_key, &t.lease_key_name) {
                (None, None) => {}
                (Some(k), Some(n)) => {
                    keys::policy_verify_key(k)?;
                    if crate::from_hex(n).is_none_or(|b| b.len() != 34) {
                        return Err(invalid("unit record: bad lease_key_name"));
                    }
                }
                _ => return Err(invalid("unit record: lease_key without its name")),
            }
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
    /// What was destroyed, in order ([`DESTROYED_EPOCH`] ...).
    #[serde(default)]
    pub destroyed: Vec<String>,
    /// What happened to the open runtime volume.
    #[serde(default)]
    pub lockdown: Option<crate::luks::Lockdown>,
    /// Steps after the essential one that failed or could not be done (the
    /// erase itself happened).
    #[serde(default)]
    pub incomplete: Vec<String>,
}

/// [`EraseReport::destroyed`]: the TPM's erase epoch moved on (every key
/// sealed to the unit is dead).
pub const DESTROYED_EPOCH: &str = "tpm_erase_epoch";
/// The UWK's TPM blobs were deleted.
pub const DESTROYED_UWK_BLOBS: &str = "uwk_tpm_blobs";
/// The runtime volume's key wrap was deleted.
pub const DESTROYED_VOLUME_WRAP: &str = "volume_key_wrap";
/// The fallback UWK file was overwritten and deleted.
pub const DESTROYED_FALLBACK_UWK: &str = "fallback_uwk_file";
/// Every LUKS2 keyslot of the runtime volume was wiped.
pub const DESTROYED_KEYSLOTS: &str = "volume_keyslots";

/// What erase acts on besides the keys in the seal directory.
#[derive(Debug, Clone, Copy, Default)]
pub struct EraseTarget<'a> {
    /// The runtime volume's LUKS2 device: its keyslots are wiped.
    /// Required for a unit without a TPM.
    pub device: Option<&'a Path>,
    /// The open mapping (`/dev/mapper/NAME`): closed, or suspended.
    pub mapper: Option<&'a str>,
    /// The runtime root, if mounted: unmounted first.
    pub mount: Option<&'a Path>,
    /// Units that use the runtime volume: stopped first.
    pub stop_units: &'a [String],
    /// Destroy the keys only: the lockdown of the open runtime volume
    /// (`stop_units`, `mount`, `mapper`) is left to the caller, which runs
    /// it later ([`Luks::lockdown`]) when its safety state allows stopping
    /// services (`robodr-responder`'s erase plan). Noted in `incomplete`.
    pub defer_lockdown: bool,
}

/// Where [`Unit::enroll_fallback`] may write the UWK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLocation {
    /// Only on a mounted dm-crypt mapping (the runtime volume).
    DmCrypt,
    /// Anywhere: tests and labs only.
    Unchecked,
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
    pub owner_auth_set: Option<bool>,
    pub lockout_auth_set: Option<bool>,
    /// What weakens this unit's protection now.
    pub warnings: Vec<String>,
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
        .custom_flags(crate::O_NOFOLLOW)
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
    lease: Option<crate::tpm::LeaseGate<'a>>,
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
            self.lease.as_ref(),
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
        Self::enroll_tpm_with(dir, unit, platform, authority, None, tpm)
    }

    /// As [`Unit::enroll_tpm`]; with `lease_key` the UWK is lease-gated
    /// (Sprint 14b, [`crate::lease`]): nothing unseals without a current
    /// lease signed by that key.
    pub fn enroll_tpm_with(
        dir: &Path,
        unit: &str,
        platform: &str,
        authority: &[u8; 65],
        lease_key: Option<&[u8; 65]>,
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
        let w = tpm.work()?;
        let name = tpm.external_key_name(&w, authority)?;
        let lease = match lease_key {
            Some(k) => Some((k, tpm.external_key_name_as(&w, k, "lease")?)),
            None => None,
        };
        let auth = match &lease {
            Some((_, ln)) => policy::uwk_auth_policy_lease(ln, unit, tpm.cfg.epoch_nv, epoch),
            None => policy::uwk_auth_policy(&name, platform, tpm.cfg.epoch_nv, epoch),
        };
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
                lease_key: lease.as_ref().map(|(k, _)| crate::to_hex(*k)),
                lease_key_name: lease.as_ref().map(|(_, n)| crate::to_hex(n)),
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
    /// which must be inside the (open) runtime volume: with
    /// [`KeyLocation::DmCrypt`] its directory must be on a dm-crypt
    /// mapping, or nothing is written.
    pub fn enroll_fallback(
        dir: &Path,
        unit: &str,
        platform: &str,
        key_path: &Path,
        location: KeyLocation,
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
        let parent = key_path
            .parent()
            .ok_or_else(|| invalid("fallback key path has no directory"))?;
        if location == KeyLocation::DmCrypt {
            // The volume's mount point exists; only check where the key
            // directory is (or would be), never create it on a plain disk.
            let mut probe = parent;
            while fs::symlink_metadata(probe).is_err() {
                probe = probe
                    .parent()
                    .ok_or_else(|| invalid("fallback key path has no existing ancestor"))?;
            }
            crate::mounts::check_on_dm_crypt(probe)?;
        }
        ensure_dir(parent)?;
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
        // Work directories of earlier releases (session contexts, in the
        // persistent seal directory) are never live now.
        crate::tpm::sweep_stale(dir);
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
    /// Refused while the TPM's owner or lockout authorization is empty: a
    /// revocation that root can undo by redefining the floor is none.
    pub fn commit_policy(&self) -> Result<u32, SealError> {
        self.tpm()?.require_ownership()?;
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
                let lease = self.current_lease()?;
                let t = self.tpm_record()?;
                let lease_key = match &t.lease_key {
                    Some(k) => Some(hex65(k)?),
                    None => None,
                };
                let lease_name = match &t.lease_key_name {
                    Some(n) => crate::from_hex(n).ok_or_else(|| invalid("lease_key_name"))?,
                    None => Vec::new(),
                };
                let authority_name = crate::from_hex(&t.policy_authority_name)
                    .ok_or_else(|| invalid("unit record: bad authority name"))?;
                let gate = match (&lease, &lease_key) {
                    (Some(l), Some(k)) => Some(crate::tpm::LeaseGate {
                        lease: l,
                        key: k,
                        key_name: &lease_name,
                        approved: l.approved(&authority_name, &self.rec.platform),
                        policy_ref: policy::lease_ref(&self.rec.unit),
                    }),
                    _ => None,
                };
                let work = self.tpm()?.work()?;
                let u = TpmUnwrapper {
                    unit: self,
                    tpm: self.tpm()?,
                    policy: &pol,
                    work: &work,
                    lease: gate,
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

    /// Overwrite and delete the fallback UWK file. `Ok(false)`: not there
    /// (the runtime volume, which holds it, is not open). Opened with
    /// `O_NOFOLLOW` and checked on the descriptor: a symlink put in its
    /// place never makes erase overwrite another file.
    fn destroy_fallback_key(&self) -> Result<bool, SealError> {
        let Some(p) = &self.rec.fallback_key else {
            return Ok(false);
        };
        let p = Path::new(p);
        let mut f = match OpenOptions::new()
            .write(true)
            .custom_flags(crate::O_NOFOLLOW)
            .open(p)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_err(p, e)),
        };
        let md = f.metadata().map_err(|e| io_err(p, e))?;
        if !md.is_file() {
            return Err(invalid(format!("{}: not a regular file", p.display())));
        }
        f.write_all(&vec![0u8; md.len() as usize])
            .and_then(|()| f.sync_all())
            .map_err(|e| io_err(p, e))?;
        drop(f);
        fs::remove_file(p).map_err(|e| io_err(p, e))?;
        Ok(true)
    }

    /// Crypto-erase (§7.6, §7.7). The **essential step**, without which
    /// nothing is reported as erased:
    ///
    /// * TPM unit: the erase epoch is incremented (every key sealed under
    ///   the old value is dead in the TPM). Then the UWK blobs and the
    ///   volume wrap are deleted, and with `target.device` the runtime
    ///   volume's LUKS2 keyslots are wiped.
    /// * Unit without a TPM: the runtime volume's LUKS2 keyslots are wiped
    ///   (`target.device` is required: the volume key exists nowhere
    ///   else, and the UWK file is inside the volume). Then the UWK file
    ///   is destroyed if the volume is open.
    ///
    /// Then the open runtime volume is locked down ([`Luks::lockdown`]:
    /// units stopped, unmounted, closed or at least suspended). The report
    /// lists exactly what was destroyed (`destroyed`) and every later step
    /// that failed (`incomplete`).
    pub fn erase(
        &self,
        trigger: &str,
        luks: &Luks,
        target: &EraseTarget<'_>,
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
            destroyed: Vec::new(),
            lockdown: None,
            incomplete: Vec::new(),
        };
        let wipe_keyslots = |dev: &Path, rep: &mut EraseReport| match luks.erase(dev) {
            Ok(()) => {
                rep.volume_header_erased = true;
                rep.destroyed.push(DESTROYED_KEYSLOTS.into());
                Ok(())
            }
            Err(e) => Err(e),
        };
        match self.rec.mode {
            Mode::Tpm => {
                let tpm = self.tpm()?;
                match tpm.epoch() {
                    Ok(v) => rep.epoch_before = Some(v),
                    Err(e) => rep
                        .incomplete
                        .push(format!("erase epoch before the increment: {e}")),
                }
                tpm.increment_epoch().map_err(|e| {
                    SealError::new(
                        e.kind,
                        format!(
                            "not erased: the erase epoch was not incremented: {}",
                            e.detail
                        ),
                    )
                })?;
                match tpm.epoch() {
                    Ok(v) => rep.epoch_after = Some(v),
                    Err(e) => rep.incomplete.push(format!(
                        "erase epoch read back after the increment failed: {e} (the TPM \
                         accepted the increment)"
                    )),
                }
                if let (Some(b), Some(a)) = (rep.epoch_before, rep.epoch_after) {
                    if a <= b {
                        return Err(SealError::new(
                            ErrorKind::Unavailable,
                            format!("not erased: the erase epoch did not move ({b} -> {a})"),
                        ));
                    }
                }
                rep.destroyed.push(DESTROYED_EPOCH.into());
                for (f, what) in [
                    (UWK_PRIV_FILE, DESTROYED_UWK_BLOBS),
                    (UWK_PUB_FILE, ""),
                    (VOLUME_WRAP_FILE, DESTROYED_VOLUME_WRAP),
                ] {
                    let p = self.dir.join(f);
                    match fs::remove_file(&p) {
                        Ok(()) if !what.is_empty() => rep.destroyed.push(what.into()),
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => rep.incomplete.push(format!("{}: {e}", p.display())),
                    }
                }
                if let Some(dev) = target.device {
                    if let Err(e) = wipe_keyslots(dev, &mut rep) {
                        rep.incomplete
                            .push(format!("volume keyslots of {}: {e}", dev.display()));
                    }
                }
            }
            Mode::Fallback => {
                let dev = target.device.ok_or_else(|| {
                    invalid(
                        "not erased: a unit without a TPM is erased by wiping its runtime \
                         volume's LUKS2 keyslots (its UWK lives inside that volume), and no \
                         device was given (--device, seal.device); nothing was destroyed",
                    )
                })?;
                wipe_keyslots(dev, &mut rep).map_err(|e| {
                    SealError::new(
                        e.kind,
                        format!(
                            "not erased: wiping the keyslots of {} failed: {}; nothing was \
                             destroyed",
                            dev.display(),
                            e.detail
                        ),
                    )
                })?;
                match self.destroy_fallback_key() {
                    Ok(true) => rep.destroyed.push(DESTROYED_FALLBACK_UWK.into()),
                    Ok(false) => rep.incomplete.push(format!(
                        "the UWK file {} is not present (the runtime volume is not open): not \
                         destroyed; it stays inside the volume, whose keyslots are wiped",
                        self.rec.fallback_key.as_deref().unwrap_or("")
                    )),
                    Err(e) => rep.incomplete.push(format!("UWK file: {e}")),
                }
            }
        }
        if target.defer_lockdown {
            rep.incomplete.push(
                "the runtime volume lockdown (stop services, unmount, close) is deferred until \
                 the safety state allows it: until then its plaintext stays readable through \
                 the open mapping"
                    .into(),
            );
        } else if target.mapper.is_some() || target.mount.is_some() || !target.stop_units.is_empty()
        {
            let l = luks.lockdown(target.stop_units, target.mount, target.mapper);
            if target.mapper.is_some() && !l.volume_locked() {
                rep.incomplete.push(
                    "the runtime volume is still open: its plaintext stays readable through \
                     the mapping until power-off"
                        .into(),
                );
            }
            rep.incomplete.extend(l.notes.iter().cloned());
            rep.lockdown = Some(l);
        } else {
            rep.incomplete.push(
                "the runtime volume was not closed (no mapper name given): if it is open, its \
                 plaintext stays readable until it is closed or the unit powers off"
                    .into(),
            );
        }
        match serde_json::to_vec(&rep) {
            Ok(bytes) => {
                if let Err(e) = write_atomic(&self.dir, ERASED_FILE, &bytes) {
                    rep.incomplete.push(format!("erase marker: {e}"));
                }
            }
            Err(e) => rep.incomplete.push(format!("erase marker: {e}")),
        }
        Ok(rep)
    }

    /// Whether the UWK is lease-gated (Sprint 14b).
    pub fn lease_gated(&self) -> bool {
        self.rec.tpm.as_ref().is_some_and(|t| t.lease_key.is_some())
    }

    /// The lease in force (`lease.json`), if any.
    pub fn lease(&self) -> Result<Option<crate::lease::Lease>, SealError> {
        match fs::symlink_metadata(self.dir.join(LEASE_FILE)) {
            Err(_) => Ok(None),
            Ok(_) => Ok(Some(crate::lease::Lease::parse(&read_small(
                &self.dir.join(LEASE_FILE),
            )?)?)),
        }
    }

    /// For a lease-gated unit: the lease, checked against the TPM's time
    /// now ([`ErrorKind::LeaseExpired`] when missing or past). `None` for
    /// a unit without a lease.
    pub fn current_lease(&self) -> Result<Option<crate::lease::Lease>, SealError> {
        if !self.lease_gated() {
            return Ok(None);
        }
        let l = self.lease()?.ok_or_else(|| {
            SealError::new(
                ErrorKind::LeaseExpired,
                "no site lease: this unit's keys unseal only under a current lease from the depot",
            )
        })?;
        l.check_now(&self.tpm()?.read_clock()?)?;
        Ok(Some(l))
    }

    /// Install a lease from the depot: signed by the enrolled lease key
    /// for this unit, and not older than the lease in force (a replayed
    /// lease never shortens or replaces a newer one).
    pub fn install_lease(&self, bytes: &[u8]) -> Result<crate::lease::Lease, SealError> {
        let t = self.tpm_record()?;
        let key = hex65(
            t.lease_key
                .as_deref()
                .ok_or_else(|| invalid("this unit was enrolled without a lease key"))?,
        )?;
        let name = crate::from_hex(&t.policy_authority_name)
            .ok_or_else(|| invalid("unit record: bad authority name"))?;
        let l = crate::lease::Lease::parse(bytes)?;
        l.verify(&key, &self.rec.unit, &name, &self.rec.platform)?;
        if let Ok(Some(cur)) = self.lease() {
            if (l.clock_before, l.resets_max, l.lease_seq)
                < (cur.clock_before, cur.resets_max, cur.lease_seq)
            {
                return Err(crate::unauthentic(format!(
                    "lease {} is older than the lease {} in force (replay)",
                    l.lease_seq, cur.lease_seq
                )));
            }
        }
        write_atomic(&self.dir, LEASE_FILE, &l.to_bytes()?)?;
        Ok(l)
    }

    /// The TPM's time (TPM units).
    pub fn tpm_time(&self) -> Result<crate::lease::TpmTime, SealError> {
        self.tpm()?.read_clock()
    }

    fn fallback_identity_path(&self) -> Result<PathBuf, SealError> {
        let k = self
            .rec
            .fallback_key
            .as_deref()
            .ok_or_else(|| invalid("no fallback key"))?;
        Ok(Path::new(k)
            .parent()
            .ok_or_else(|| invalid("fallback key has no directory"))?
            .join(FALLBACK_UIK_FILE))
    }

    /// Create the AK and the unit identity key once (Sprint 14a); their
    /// public key. Without a TPM the identity key is a file next to the
    /// fallback UWK (inside the runtime volume).
    pub fn ensure_identity(&self) -> Result<[u8; 65], SealError> {
        match self.rec.mode {
            Mode::Tpm => {
                let tpm = self.tpm()?;
                if fs::symlink_metadata(self.dir.join(AK_PRIV_FILE)).is_err() {
                    let (pu, pr) = tpm.create_ak()?;
                    write_atomic(&self.dir, AK_PUB_FILE, &pu)?;
                    write_atomic(&self.dir, AK_PRIV_FILE, &pr)?;
                }
                if fs::symlink_metadata(self.dir.join(UIK_PRIV_FILE)).is_err() {
                    let (pu, pr) = tpm.create_uik()?;
                    write_atomic(&self.dir, UIK_PUB_FILE, &pu)?;
                    write_atomic(&self.dir, UIK_PRIV_FILE, &pr)?;
                }
                self.identity_public()
            }
            Mode::Fallback => {
                let p = self.fallback_identity_path()?;
                if fs::symlink_metadata(&p).is_err() {
                    let pubp = p.with_extension("pub");
                    keys::policy_generate(&p, &pubp)?;
                }
                Ok(keys::policy_load(&p)?.public())
            }
        }
    }

    /// The unit identity key's public key.
    pub fn identity_public(&self) -> Result<[u8; 65], SealError> {
        match self.rec.mode {
            Mode::Tpm => {
                let b = read_small(&self.dir.join(UIK_PUB_FILE))?;
                crate::attest::parse_tpm2b_public(&b)?.p256()
            }
            Mode::Fallback => Ok(keys::policy_load(&self.fallback_identity_path()?)?.public()),
        }
    }

    /// ECDSA P-256 (DER) by the identity key over a SHA-256 digest: the
    /// TPM signs for a TPM unit.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, SealError> {
        match self.rec.mode {
            Mode::Tpm => {
                let pu = read_small(&self.dir.join(UIK_PUB_FILE))?;
                let pr = read_small(&self.dir.join(UIK_PRIV_FILE))?;
                self.tpm()?.sign_digest((&pu, &pr), digest)
            }
            Mode::Fallback => {
                keys::policy_load(&self.fallback_identity_path()?)?.sign_digest(digest)
            }
        }
    }

    fn ak_blobs(&self) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        Ok((
            read_small(&self.dir.join(AK_PUB_FILE))?,
            read_small(&self.dir.join(AK_PRIV_FILE))?,
        ))
    }

    /// A TPM attestation (a quote by the AK) qualified by `digest`: its
    /// `clockInfo` is the TPM's own time (unit reports, 14b review).
    pub fn time_attest(&self, digest: &[u8; 32]) -> Result<crate::enrol::SignedHex, SealError> {
        if self.rec.mode != Mode::Tpm {
            return Err(invalid("time attestation needs a TPM unit"));
        }
        let t = self.tpm()?;
        let (akp, akr) = self.ak_blobs()?;
        let idx: Vec<u8> = match self.policy() {
            Ok(p) if !p.pcrs.is_empty() => p.pcrs.iter().map(|(i, _)| *i).collect(),
            _ => vec![0],
        };
        let (q, _) = t.quote((&akp, &akr), &idx, digest)?;
        Ok(crate::enrol::SignedHex {
            attest: crate::to_hex(&q.attest),
            sig: crate::to_hex(&q.sig),
        })
    }

    /// The enrolment request for the depot's `nonce` (Sprint 14a,
    /// [`crate::enrol`]).
    pub fn enrol_request(&self, nonce: &[u8; 32]) -> Result<crate::enrol::EnrolRequest, SealError> {
        use crate::enrol::*;
        let identity = self.ensure_identity()?;
        let tpm = match self.rec.mode {
            Mode::Fallback => None,
            Mode::Tpm => {
                let t = self.tpm()?;
                let (akp, akr) = self.ak_blobs()?;
                let (up, ur) = self.uwk_blobs()?;
                let ip = read_small(&self.dir.join(UIK_PUB_FILE))?;
                let ir = read_small(&self.dir.join(UIK_PRIV_FILE))?;
                let c = t.certify_with_ak((&akp, &akr), &[("uwk", &up, &ur), ("uik", &ip, &ir)])?;
                let pol = self.policy()?;
                let pol_bytes = read_small(&self.dir.join(POLICY_FILE))?;
                let idx: Vec<u8> = pol.pcrs.iter().map(|(i, _)| *i).collect();
                let (q, values) = t.quote((&akp, &akr), &idx, nonce)?;
                let hx = crate::to_hex;
                let sh = |s: &crate::tpm_ident::Signed| SignedHex {
                    attest: hx(&s.attest),
                    sig: hx(&s.sig),
                };
                Some(TpmEvidence {
                    ek_public: hx(&t.ek_public()?),
                    ek_certificate: t.ek_certificate()?.map(|c| hx(&c)),
                    ak_public: hx(&akp),
                    uwk_public_area: hx(&up),
                    uwk_certify: sh(&c[0]),
                    uik_public_area: hx(&ip),
                    uik_certify: sh(&c[1]),
                    policy: hx(&pol_bytes),
                    quote: QuoteHex {
                        attest: hx(&q.attest),
                        sig: hx(&q.sig),
                        pcrs: values
                            .iter()
                            .map(|(i, v)| policy::PcrValue {
                                index: *i,
                                value: hx(v),
                            })
                            .collect(),
                    },
                })
            }
        };
        Ok(EnrolRequest {
            format: REQUEST_FORMAT.into(),
            unit: self.rec.unit.clone(),
            platform: self.rec.platform.clone(),
            nonce: crate::to_hex(nonce),
            record: self.rec.clone(),
            identity_public: crate::to_hex(&identity),
            tpm,
        })
    }

    /// Answer the depot's credential challenge with this TPM's EK and AK.
    pub fn enrol_activate(
        &self,
        c: &crate::enrol::EnrolChallenge,
    ) -> Result<crate::enrol::EnrolResponse, SealError> {
        if c.unit != self.rec.unit {
            return Err(crate::unauthentic(format!(
                "challenge for unit {}, this is {}",
                c.unit, self.rec.unit
            )));
        }
        let cred = crate::from_hex(&c.credential).ok_or_else(|| invalid("credential hex"))?;
        let (akp, akr) = self.ak_blobs()?;
        let secret = self.tpm()?.activate((&akp, &akr), &cred)?;
        Ok(crate::enrol::EnrolResponse {
            format: crate::enrol::RESPONSE_FORMAT.into(),
            unit: self.rec.unit.clone(),
            nonce: c.nonce.clone(),
            secret: crate::to_hex(&secret),
        })
    }

    /// Status (reads the TPM for TPM units).
    pub fn status(&self) -> Status {
        let tpm_rec = self.rec.tpm.as_ref();
        let tpm = self.tpm.as_ref();
        let own = tpm.and_then(|t| t.ownership().ok());
        let mut warnings = Vec::new();
        if own.is_some_and(|o| !o.ok()) {
            warnings.push(crate::tpm::OWNERSHIP_REQUIRED.to_string());
        }
        Status {
            unit: self.rec.unit.clone(),
            mode: self.rec.mode,
            erased: self.is_erased(),
            epoch_enrolled: tpm_rec.map(|t| t.epoch),
            epoch_now: tpm.and_then(|t| t.epoch().ok()),
            policy_version: self.policy().ok().map(|p| p.doc.version),
            floor_bits: tpm.and_then(|t| t.floor_bits().ok()),
            owner_auth_set: own.map(|o| o.owner_auth_set),
            lockout_auth_set: own.map(|o| o.lockout_auth_set),
            warnings,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{Output, Runner};
    use std::sync::Mutex;
    use std::time::Duration;

    /// A TPM whose epoch counter increments, but whose read-back after the
    /// increment fails (L2 of the review).
    #[derive(Debug, Default)]
    struct ReadbackFails {
        incremented: Mutex<bool>,
    }

    impl Runner for ReadbackFails {
        fn run(
            &self,
            program: &Path,
            _args: &[String],
            _env: &[(&str, &str)],
            _stdin: Option<&[u8]>,
            _timeout: Duration,
        ) -> Result<Output, SealError> {
            let name = program.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let mut inc = self.incremented.lock().unwrap();
            let ok = |stdout: Vec<u8>| Output {
                status: Some(0),
                stdout: Zeroizing::new(stdout),
                stderr: Zeroizing::new(Vec::new()),
            };
            Ok(match name {
                "tpm2_nvread" if !*inc => ok(5u64.to_be_bytes().to_vec()),
                "tpm2_nvread" => Output {
                    status: Some(1),
                    stdout: Zeroizing::new(Vec::new()),
                    stderr: Zeroizing::new(b"ERROR: bus glitch".to_vec()),
                },
                "tpm2_nvincrement" => {
                    *inc = true;
                    ok(Vec::new())
                }
                _ => ok(Vec::new()),
            })
        }
    }

    fn tpm_unit(dir: &Path, runner: Box<dyn Runner>) -> Unit {
        let rec = UnitRecord {
            format: UNIT_FORMAT.into(),
            unit: "ugv-07".into(),
            platform: "ugv-x1".into(),
            mode: Mode::Tpm,
            uwk_public: String::new(),
            tpm: Some(TpmRecord {
                srk: "0x81000001".into(),
                epoch_nv: "0x01500040".into(),
                epoch: 5,
                floor_nv: "0x01500041".into(),
                policy_authority: String::new(),
                policy_authority_name: String::new(),
                auth_policy: String::new(),
                lease_key: None,
                lease_key_name: None,
            }),
            fallback_key: None,
        };
        let tpm = Tpm::new(crate::tpm::TpmConfig::default(), runner).unwrap();
        Unit {
            dir: dir.to_path_buf(),
            rec,
            tpm: Some(tpm),
        }
    }

    #[test]
    fn a_successful_increment_is_the_erase_even_if_the_readback_fails() {
        let d = std::env::temp_dir().join(format!("robodr-seal-l2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let u = tpm_unit(&d, Box::<ReadbackFails>::default());
        let r = u.erase("operator", &Luks::system(), &EraseTarget::default());
        let _ = fs::remove_dir_all(&d);
        let rep = r.expect("the epoch moved: that is the erase");
        assert_eq!(rep.destroyed, [DESTROYED_EPOCH]);
        assert_eq!(rep.epoch_before, Some(5));
        assert_eq!(rep.epoch_after, None);
        assert!(
            rep.incomplete.iter().any(|n| n.contains("read back")),
            "{:?}",
            rep.incomplete
        );
    }
}
