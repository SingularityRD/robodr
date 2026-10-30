//! The depot's operations (crate docs). Every operation that changes
//! anything refuses while the database is locked ([`crate::db`]).

use crate::config::Config;
use crate::db::{
    Attestation, Db, DeployState, Deployment as DbDeployment, EnrolState, LastReport, Rollout,
    RolloutState, Rpk, Store, Unit,
};
use crate::{err, rules, x509, DepotError};
use robodr_blackbox::Signer;
use robodr_events::Severity;
use robodr_pkg::common::{is_label, sha256_hex, to_canonical};
use robodr_pkg::deployment::{
    self, Deployment, Item, MaintenanceWindow, Rollout as DocRollout, Targets, WrappedKey,
    DEPLOYMENT_FORMAT, DEPLOYMENT_SIG_DOMAIN,
};
use robodr_pkg::sig::{Role, SignatureSet};
use robodr_release::ops::{self, ChainMode, SiteTrust};
use robodr_seal::keys::PolicyKey;
use robodr_seal::wrap::X25519Secret;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Domain of operator approvals of an enrolment.
pub const ENROLMENT_SIG_DOMAIN: &[u8] = b"robodr-depot/enrolment/v1\0";
/// Domain of operator decisions (resume, abort, revoke, reanchor).
pub const DECISION_SIG_DOMAIN: &[u8] = b"robodr-depot/decision/v1\0";
/// How long an operation waits for the depot's lock.
pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);
/// Most units in one stage.
pub const MAX_STAGE_UNITS: usize = 4096;

/// What an enrolment approval covers.
#[derive(Debug, Serialize)]
struct EnrolmentStatement<'a> {
    site: &'a str,
    unit: &'a str,
    ring: &'a str,
    platform: &'a str,
    record: &'a robodr_seal::unit::UnitRecord,
    identity_public: &'a str,
    ak_name: Option<&'a str>,
    ek: Option<&'a str>,
    attestation: Attestation,
}

/// The digest operators sign to approve a unit's enrolment.
pub fn enrolment_digest(site: &str, u: &Unit) -> Result<Vec<u8>, DepotError> {
    let (Some(record), Some(platform), Some(identity)) =
        (&u.record, &u.platform, &u.identity_public)
    else {
        return Err(err("the unit has not answered its challenge"));
    };
    let s = EnrolmentStatement {
        site,
        unit: &u.unit,
        ring: &u.ring,
        platform,
        record,
        identity_public: identity,
        ak_name: u.ak_name.as_deref(),
        ek: u.ek.as_deref(),
        attestation: u.attestation,
    };
    to_canonical(&s).map_err(|e| err(e.to_string()))
}

/// The statement operators sign for a decision.
pub fn decision(site: &str, what: &str, subject: &str, n: u64) -> Vec<u8> {
    format!("{site}\0{what}\0{subject}\0{n}").into_bytes()
}

/// Rank of a ring for stage ordering.
fn ring_rank(r: &str) -> Option<u32> {
    match r {
        "lab" => Some(0),
        "canary" => Some(1),
        _ => r
            .strip_prefix("ring-")
            .and_then(|n| n.parse::<u32>().ok())
            .filter(|_| deployment::is_ring(r))
            .map(|n| n + 1),
    }
}

/// Rollout parameters.
#[derive(Debug, Clone)]
pub struct RolloutParams {
    pub batch_size: u32,
    pub soak_s: u32,
    pub max_failures: u32,
    pub validity_s: u64,
    pub maintenance_window: Option<MaintenanceWindow>,
    /// Least distribution (§4.3): only these units of each ring (the
    /// trust file still decides their rings); `None`: every unit.
    pub units: Option<Vec<String>>,
}

impl Default for RolloutParams {
    fn default() -> Self {
        Self {
            batch_size: 1,
            soak_s: 600,
            max_failures: 0,
            validity_s: 30 * 86400,
            maintenance_window: None,
            units: None,
        }
    }
}

/// DER certificates.
type DerCerts = Vec<Vec<u8>>;

/// The site depot.
pub struct Depot {
    pub cfg: Config,
    pub site: SiteTrust,
    store: Store,
    pub db: Db,
    signing: Box<dyn Signer>,
    wrap: X25519Secret,
    lease_key: Option<PolicyKey>,
    ca: PolicyKey,
    authority: [u8; 65],
    findings: Option<robodr_deliverd::findings::Findings>,
    /// The single-writer lock ([`crate::lock`]), held while open.
    _lock: std::fs::File,
}

impl std::fmt::Debug for Depot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Depot")
            .field("site", &self.cfg.site)
            .field("generation", &self.db.generation)
            .finish_non_exhaustive()
    }
}

fn fail(e: impl std::fmt::Display) -> DepotError {
    err(e.to_string())
}

fn write_file(p: &Path, b: &[u8], mode: u32) -> Result<(), DepotError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| err(format!("{}: {e}", d.display())))?;
    }
    let tmp = p.with_extension("tmp-write");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| err(format!("{}: {e}", tmp.display())))?;
    f.write_all(b)
        .and_then(|()| f.sync_all())
        .map_err(|e| err(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, p).map_err(|e| err(format!("{}: {e}", p.display())))
}

fn anchor_store(cfg: &Config) -> Result<Store, DepotError> {
    let anchor = match &cfg.anchor {
        None => None,
        Some(a) => {
            let tcfg = robodr_seal::tpm::TpmConfig {
                tcti: a.tcti.clone(),
                work_dir: a.work_dir.clone(),
                tools_dir: a.tools_dir.clone(),
                ..Default::default()
            };
            let tpm = robodr_seal::tpm::Tpm::new(tcfg, Box::new(robodr_seal::cmd::System))
                .map_err(fail)?;
            let index = robodr_seal::unit::parse_handle(&a.index, 0x01).map_err(fail)?;
            Some(crate::db::Anchor { tpm, index })
        }
    };
    Ok(Store {
        path: cfg.state_dir.join(crate::db::DB_FILE),
        anchor,
    })
}

impl Depot {
    /// First start: create the state directory, the site's trust anchor
    /// from `trust` (under the pinned roots and site), the unit CA
    /// certificate, the TLS server key and certificate (with `serve`), and
    /// an empty database.
    pub fn init(cfg: &Config, trust: &Path, now: u64) -> Result<(), DepotError> {
        for d in [
            "trust",
            "store/bundles",
            "chains",
            "deployments",
            "units",
            "tls",
            "work",
        ] {
            let p = cfg.state_dir.join(d);
            std::fs::create_dir_all(&p).map_err(|e| err(format!("{}: {e}", p.display())))?;
        }
        ops::init_anchor(trust, &cfg.anchor_path(), &cfg.roots, &cfg.site, now).map_err(fail)?;
        let ca = robodr_seal::keys::policy_load(&cfg.keys.ca).map_err(fail)?;
        let ca_name = format!("{} depot unit CA", cfg.site);
        let ca_der = x509::issue(
            &x509::Params {
                issuer_cn: &ca_name,
                subject_cn: &ca_name,
                subject_public: &ca.public(),
                serial: 1,
                not_before: now.saturating_sub(3600),
                not_after: now + 20 * 366 * 86400,
                kind: x509::Kind::Ca,
            },
            &ca,
        )?;
        write_file(
            &cfg.state_dir.join("tls/ca.pem"),
            x509::pem("CERTIFICATE", &ca_der).as_bytes(),
            0o644,
        )?;
        if let Some(s) = &cfg.serve {
            let k = robodr_seal::wrap::p256_random().map_err(fail)?;
            let public = robodr_seal::wrap::p256_public_bytes(&k.public_key());
            let mut secret = zeroize::Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(&k.to_bytes());
            let key = zeroize::Zeroizing::new(x509::sec1_private_key(&secret, &public));
            write_file(
                &cfg.state_dir.join("tls/server.key"),
                x509::pem("EC PRIVATE KEY", &key).as_bytes(),
                0o600,
            )?;
            let der = x509::issue(
                &x509::Params {
                    issuer_cn: &ca_name,
                    subject_cn: &s.server_name,
                    subject_public: &public,
                    serial: 2,
                    not_before: now.saturating_sub(3600),
                    not_after: now + 5 * 366 * 86400,
                    kind: x509::Kind::Server(vec![s.server_name.clone()]),
                },
                &ca,
            )?;
            write_file(
                &cfg.state_dir.join("tls/server.pem"),
                x509::pem("CERTIFICATE", &der).as_bytes(),
                0o644,
            )?;
        }
        let _lock = crate::lock::lock(&cfg.state_dir.join("depot.lock"), LOCK_WAIT)?;
        let store = anchor_store(cfg)?;
        let (mut db, _) = store.open(&cfg.site)?;
        if db.generation != 0 {
            return Err(err("a depot database exists already"));
        }
        db.cert_serial = 3;
        store.save(&mut db)
    }

    /// Open the depot at `now`: trust anchor (the anchor itself as the
    /// presented file), database (judged against the anchor), keys.
    pub fn open(cfg: Config, now: u64) -> Result<Self, DepotError> {
        let lock = crate::lock::lock(&cfg.state_dir.join("depot.lock"), LOCK_WAIT)?;
        let a = cfg.anchor_path();
        let site = SiteTrust::anchored(&a, &a, &cfg.roots, &cfg.site, now).map_err(fail)?;
        let store = anchor_store(&cfg)?;
        let (db, fresh_lock) = store.open(&cfg.site)?;
        let kf = robodr_blackbox::KeyFile::load_secret(&cfg.keys.signing).map_err(fail)?;
        let signing_public = kf
            .public_key()
            .ok_or_else(|| err("the depot signing key must be Ed25519"))?;
        let signing = kf.signer().map_err(fail)?;
        let wrap = robodr_seal::keys::x25519_load(&cfg.keys.wrap).map_err(fail)?;
        let lease_key = match &cfg.keys.lease {
            Some(p) => Some(robodr_seal::keys::policy_load(p).map_err(fail)?),
            None => None,
        };
        let ca = robodr_seal::keys::policy_load(&cfg.keys.ca).map_err(fail)?;
        let authority =
            robodr_seal::keys::policy_load_public(&cfg.enrolment.policy_authority).map_err(fail)?;
        let findings = cfg.findings.as_ref().map(|f| {
            robodr_deliverd::findings::Findings::new(
                f,
                &cfg.depot_id,
                "robodr-depot",
                &cfg.site,
                None,
            )
        });
        let mut d = Self {
            cfg,
            site,
            store,
            db,
            signing,
            wrap,
            lease_key,
            ca,
            authority,
            findings,
            _lock: lock,
        };
        // The depot key must be the trust file's depot key; the wrap key
        // one the trust file lists (when it lists any).
        if !d.site.file().depot_keys.iter().any(|k| {
            robodr_seal::from_hex(&k.public_hex).as_deref() == Some(signing_public.as_slice())
        }) {
            return Err(err(
                "the depot signing key is not a depot key of the site trust file",
            ));
        }
        let wfp = robodr_seal::wrap::Recipient::X25519(d.wrap.public()).fingerprint();
        let listed = d.site.depot_wrap_fingerprints();
        if !listed.is_empty() && !listed.contains(&wfp) {
            return Err(err(
                "the depot wrapping key is not listed in the site trust file",
            ));
        }
        if fresh_lock {
            // The lock is kept in the database (it moves the anchor on), so
            // it is reported once and lifted only by `reanchor`.
            let why = d.db.locked.clone().unwrap_or_default();
            d.save()?;
            d.finding(
                rules::LOCKED,
                Severity::Critical,
                format!("the depot database failed its anti-rollback check: {why}"),
                now,
            );
        }
        Ok(d)
    }

    fn finding(&mut self, rule: &'static str, sev: Severity, detail: String, now: u64) {
        let trust = (self.site.file().version, self.site.digest.clone());
        if let Some(f) = &mut self.findings {
            let _ = f.emit(
                &robodr_deliverd::findings::Finding {
                    rule,
                    severity: sev,
                    detail,
                    safety: robodr_responder::SafetyState::Unknown,
                    evidence: None,
                },
                Some((trust.0, &trust.1)),
                now.saturating_mul(1000),
            );
        }
    }

    fn unlocked(&self) -> Result<(), DepotError> {
        match &self.db.locked {
            Some(w) => Err(err(format!(
                "the depot is locked (database anti-rollback: {w}); robodr-depot reanchor"
            ))),
            None => Ok(()),
        }
    }

    fn save(&mut self) -> Result<(), DepotError> {
        self.store.save(&mut self.db)
    }

    /// Advance the site trust to a rotation of the anchor.
    pub fn update_trust(&mut self, presented: &Path, now: u64) -> Result<u64, DepotError> {
        self.unlocked()?;
        let a = self.cfg.anchor_path();
        let st = SiteTrust::anchored(presented, &a, &self.cfg.roots, &self.cfg.site, now)
            .map_err(fail)?;
        ops::commit_anchor(&st).map_err(fail)?;
        self.site =
            SiteTrust::anchored(&a, &a, &self.cfg.roots, &self.cfg.site, now).map_err(fail)?;
        Ok(self.site.file().version)
    }

    fn bundle_dir(&self, label: &str) -> PathBuf {
        self.cfg.state_dir.join("store/bundles").join(label)
    }

    // ------------------------------------------------------------ import --

    /// Import a bundle with its entry report (`report`, signature at
    /// `report.sig`). Returns the bundle label.
    pub fn import(&mut self, bundle: &Path, report: &Path, now: u64) -> Result<String, DepotError> {
        let r = self.import_inner(bundle, report, now);
        if let Err(e) = &r {
            self.finding(
                rules::IMPORT_REFUSED,
                Severity::High,
                format!("bundle import refused: {e}"),
                now,
            );
        }
        r
    }

    fn import_inner(
        &mut self,
        bundle: &Path,
        report: &Path,
        now: u64,
    ) -> Result<String, DepotError> {
        use robodr_pkg::bundle::{
            verify_bundle_manifest, BUNDLE_FILE, BUNDLE_SIG_FILE, MAX_BUNDLE_BYTES,
        };
        use robodr_release::fsio::read_capped;
        self.unlocked()?;
        self.site.check_fresh(now).map_err(fail)?;
        let bb = read_capped(&bundle.join(BUNDLE_FILE), MAX_BUNDLE_BYTES).map_err(fail)?;
        let bs = read_capped(
            &bundle.join(BUNDLE_SIG_FILE),
            robodr_pkg::sig::MAX_SIGSET_BYTES,
        )
        .map_err(fail)?;
        let vb = verify_bundle_manifest(&bb, &bs, &self.site.trust).map_err(fail)?;
        let rb = read_capped(report, robodr_pkg::entry::MAX_ENTRY_BYTES).map_err(fail)?;
        let rs =
            read_capped(&ops::sig_path(report), robodr_pkg::sig::MAX_SIGSET_BYTES).map_err(fail)?;
        let er = robodr_pkg::entry::verify_entry_report(&rb, &rs, &self.site.trust, &vb, now)
            .map_err(fail)?;
        let m = &vb.manifest;
        let label = format!("{}-{:06}", m.programme, m.bundle_seq);
        if let Some(b) = self.db.bundles.get(&label) {
            if b.hash == vb.hash {
                return Ok(label);
            }
        }
        let chain_path = self
            .cfg
            .state_dir
            .join("chains")
            .join(format!("{}.json", m.programme));
        let chain = if chain_path.exists() {
            ChainMode::State(chain_path.clone())
        } else {
            ChainMode::Genesis
        };
        let dest = self.bundle_dir(&label);
        if dest.exists() {
            // A copy left by an import that failed before its database
            // write: the chain decides again below.
            std::fs::remove_dir_all(&dest).map_err(|e| err(e.to_string()))?;
        }
        let rep = ops::import_bundle(bundle, &dest, &self.site, &chain, now).map_err(fail)?;
        ops::commit_chain(&chain_path, &rep.bundle, &self.site).map_err(fail)?;
        for v in &rep.rpks {
            let e = rep
                .bundle
                .manifest
                .rpks
                .iter()
                .find(|x| x.digest == v.digest)
                .ok_or_else(|| err("RPK not listed"))?;
            self.db.rpks.entry(v.digest.clone()).or_insert(Rpk {
                name: v.manifest.name.clone(),
                serial: v.manifest.version.serial,
                arch: v.manifest.arch.as_str().into(),
                platform: v.manifest.platform.clone(),
                kind: serde_json::to_value(v.manifest.kind)
                    .ok()
                    .and_then(|k| k.as_str().map(str::to_string))
                    .unwrap_or_default(),
                sealed: v.manifest.is_sealed(),
                bundle: label.clone(),
                dir: e.dir.clone(),
            });
        }
        self.db.bundles.insert(
            label.clone(),
            crate::db::Bundle {
                programme: m.programme.clone(),
                seq: m.bundle_seq,
                hash: vb.hash.clone(),
                entry_report: er.digest.clone(),
                station: er.report.station.clone(),
                imported_at: now,
            },
        );
        // Keep the report as evidence next to the bundle.
        write_file(&dest.with_extension("entry.json"), &rb, 0o644)?;
        write_file(&dest.with_extension("entry.json.sig"), &rs, 0o644)?;
        self.save()?;
        Ok(label)
    }

    // --------------------------------------------------------- enrolment --

    /// Start a unit's enrolment: a fresh nonce (hex). The unit must be
    /// assigned to a ring by the trust file.
    pub fn enrol_begin(&mut self, unit: &str, now: u64) -> Result<String, DepotError> {
        self.unlocked()?;
        if !is_label(unit) {
            return Err(err("bad unit label"));
        }
        let ring = self
            .site
            .ring_of_unit(unit)
            .ok_or_else(|| {
                err(format!(
                    "unit {unit} is not assigned to a ring by the trust file"
                ))
            })?
            .to_string();
        if let Some(u) = self.db.units.get(unit) {
            if u.state == EnrolState::Enrolled {
                return Err(err(format!(
                    "unit {unit} is enrolled; revoke it first to enrol it again"
                )));
            }
        }
        let nonce = robodr_seal::to_hex(&crate::random32()?);
        let prev = self.db.units.get(unit).cloned();
        self.db.units.insert(
            unit.into(),
            Unit {
                unit: unit.into(),
                ring,
                state: EnrolState::Begun,
                attestation: Attestation::Unknown,
                nonce: Some(nonce.clone()),
                secret_sha256: None,
                record: None,
                platform: None,
                identity_public: None,
                ak_name: None,
                ek: None,
                policy_version: None,
                approvals: None,
                enrolled_at: None,
                cert_serial: None,
                last_report: prev.as_ref().and_then(|p| p.last_report.clone()),
                erased: false,
                lease_seq: prev.map_or(0, |p| p.lease_seq),
            },
        );
        let _ = now;
        self.save()?;
        Ok(nonce)
    }

    /// (EK CA certificates, intermediates), DER.
    fn ek_cas(&self) -> Result<(DerCerts, DerCerts), DepotError> {
        let read_dir = |d: &Path| -> Result<Vec<Vec<u8>>, DepotError> {
            let mut out = Vec::new();
            let rd = std::fs::read_dir(d).map_err(|e| err(format!("{}: {e}", d.display())))?;
            let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            files.sort();
            for f in files.into_iter().take(256) {
                let b = robodr_release::fsio::read_capped(&f, 1 << 20).map_err(fail)?;
                out.extend(x509::certs_of(&b)?);
            }
            Ok(out)
        };
        let cas: Vec<Vec<u8>> = read_dir(&self.cfg.enrolment.ek_cas)?
            .into_iter()
            .filter(|c| self.site.accepts_ek_ca(&sha256_hex(c)))
            .collect();
        let inter = match &self.cfg.enrolment.ek_intermediates {
            Some(d) => read_dir(d)?,
            None => Vec::new(),
        };
        Ok((cas, inter))
    }

    /// Verify a unit's enrolment request and return the credential
    /// challenge (JSON bytes); for an accepted unit without a TPM, `None`
    /// (activated at once, unattested).
    pub fn enrol_verify(
        &mut self,
        request: &[u8],
        now: u64,
    ) -> Result<Option<Vec<u8>>, DepotError> {
        let r = self.enrol_verify_inner(request, now);
        if let Err(e) = &r {
            self.finding(
                rules::ENROLMENT_REFUSED,
                Severity::High,
                format!("enrolment refused: {e}"),
                now,
            );
        }
        r
    }

    fn enrol_verify_inner(
        &mut self,
        request: &[u8],
        now: u64,
    ) -> Result<Option<Vec<u8>>, DepotError> {
        use robodr_seal::enrol;
        self.unlocked()?;
        let req = enrol::parse_request(request).map_err(fail)?;
        let u = self
            .db
            .units
            .get(&req.unit)
            .filter(|u| u.state == EnrolState::Begun)
            .ok_or_else(|| {
                err(format!(
                    "no enrolment of {} is waiting for a request",
                    req.unit
                ))
            })?
            .clone();
        let nonce: [u8; 32] = u
            .nonce
            .as_deref()
            .and_then(robodr_seal::from_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err("no nonce"))?;
        let lease_pub = self.lease_key.as_ref().map(PolicyKey::public);
        let checked = enrol::verify_request(
            &req,
            &enrol::Expect {
                authority: &self.authority,
                lease_key: lease_pub.as_ref(),
                nonce: &nonce,
            },
        )
        .map_err(fail)?;
        let mut nu = u.clone();
        nu.record = Some(req.record.clone());
        nu.platform = Some(req.platform.clone());
        nu.identity_public = Some(req.identity_public.clone());
        nu.policy_version = checked.policy_version;
        let challenge = match (&checked.ek, &checked.ak_name) {
            (Some(ek), Some(ak_name)) => {
                let cert = checked.ek_certificate.as_ref().ok_or_else(|| {
                    err("the TPM has no EK certificate: not a TPM the site accepts")
                })?;
                let (cas, inter) = self.ek_cas()?;
                if cas.is_empty() {
                    return Err(err(
                        "no EK CA certificate whose digest the trust file lists (ek_ca_certs)",
                    ));
                }
                x509::verify_ek_chain(cert, &cas, &inter, ek, now)?;
                let secret = crate::random32()?;
                let cred = self.make_credential(&ek.tpmt, ak_name, &secret)?;
                nu.ak_name = Some(robodr_seal::to_hex(ak_name));
                nu.ek = Some(sha256_hex(&ek.tpmt));
                nu.secret_sha256 = Some(sha256_hex(&secret));
                nu.state = EnrolState::Challenged;
                nu.attestation = Attestation::Verified;
                let c = enrol::EnrolChallenge {
                    format: enrol::CHALLENGE_FORMAT.into(),
                    unit: req.unit.clone(),
                    nonce: req.nonce.clone(),
                    credential: robodr_seal::to_hex(&cred),
                };
                Some(serde_json::to_vec(&c).map_err(fail)?)
            }
            _ => {
                if !self.cfg.enrolment.allow_without_tpm {
                    return Err(err(
                        "a unit without a TPM: this site does not accept unattested units \
                         (enrolment.allow_without_tpm)",
                    ));
                }
                nu.state = EnrolState::Activated;
                nu.attestation = Attestation::Unknown;
                nu.nonce = None;
                None
            }
        };
        self.db.units.insert(req.unit.clone(), nu);
        self.save()?;
        Ok(challenge)
    }

    /// `TPM2_MakeCredential` in software (`tpm2_makecredential -T none`).
    fn make_credential(
        &self,
        ek_tpmt: &[u8],
        ak_name: &[u8],
        secret: &[u8; 32],
    ) -> Result<Vec<u8>, DepotError> {
        use robodr_seal::cmd::Runner;
        let w = self.cfg.state_dir.join("work");
        std::fs::create_dir_all(&w).map_err(|e| err(e.to_string()))?;
        let tag = robodr_seal::to_hex(&crate::random32()?[..8]);
        let ek = w.join(format!("ek-{tag}.pub"));
        let sp = w.join(format!("secret-{tag}"));
        let out = w.join(format!("cred-{tag}"));
        let mut tpm2b = (ek_tpmt.len() as u16).to_be_bytes().to_vec();
        tpm2b.extend_from_slice(ek_tpmt);
        write_file(&ek, &tpm2b, 0o600)?;
        write_file(&sp, secret, 0o600)?;
        let tools = self
            .cfg
            .anchor
            .as_ref()
            .map_or_else(|| PathBuf::from("/usr/bin"), |a| a.tools_dir.clone());
        let prog = robodr_seal::cmd::tool(&tools, "tpm2_makecredential").map_err(fail)?;
        let r = robodr_seal::cmd::System.run(
            &prog,
            &[
                "-T".into(),
                "none".into(),
                "-e".into(),
                ek.display().to_string(),
                "-s".into(),
                sp.display().to_string(),
                "-n".into(),
                robodr_seal::to_hex(ak_name),
                "-o".into(),
                out.display().to_string(),
            ],
            &[],
            None,
            std::time::Duration::from_secs(30),
        );
        let _ = std::fs::remove_file(&sp);
        let _ = std::fs::remove_file(&ek);
        let o = r.map_err(fail)?;
        if !o.ok() {
            let _ = std::fs::remove_file(&out);
            return Err(err(format!("tpm2_makecredential: {}", o.error_line())));
        }
        let c = std::fs::read(&out).map_err(|e| err(e.to_string()));
        let _ = std::fs::remove_file(&out);
        c
    }

    /// The unit's answer to the challenge.
    pub fn enrol_finish(&mut self, response: &[u8], now: u64) -> Result<String, DepotError> {
        let r = (|| {
            self.unlocked()?;
            let resp = robodr_seal::enrol::parse_response(response).map_err(fail)?;
            let u = self
                .db
                .units
                .get_mut(&resp.unit)
                .filter(|u| u.state == EnrolState::Challenged)
                .ok_or_else(|| err(format!("no challenge of {} is open", resp.unit)))?;
            let ok_nonce = u.nonce.as_deref() == Some(resp.nonce.as_str());
            let secret = robodr_seal::from_hex(&resp.secret).unwrap_or_default();
            let ok_secret = u
                .secret_sha256
                .as_deref()
                .is_some_and(|h| robodr_seal::ct_eq(h.as_bytes(), sha256_hex(&secret).as_bytes()));
            // One answer per challenge: a wrong one closes it.
            u.secret_sha256 = None;
            u.nonce = None;
            if !(ok_nonce && ok_secret) {
                u.state = EnrolState::Revoked;
                self.save()?;
                return Err(err(format!(
                    "unit {}: the credential was not activated by the TPM that holds the EK and the \
                     AK (wrong secret): enrolment closed",
                    resp.unit
                )));
            }
            u.state = EnrolState::Activated;
            let unit = resp.unit.clone();
            self.save()?;
            Ok(unit)
        })();
        if let Err(e) = &r {
            self.finding(
                rules::ENROLMENT_REFUSED,
                Severity::High,
                format!("enrolment refused: {e}"),
                now,
            );
        }
        r
    }

    fn operator_quorum(&self, ring_prod: bool) -> usize {
        let q = &self.site.file().quorum;
        if ring_prod {
            q.operator_prod as usize
        } else {
            q.operator_lab as usize
        }
    }

    /// An operator approves an activated enrolment; at the production
    /// operator quorum the unit is enrolled (§8: two operators). Returns
    /// whether it is enrolled now.
    pub fn enrol_approve(
        &mut self,
        unit: &str,
        key: &dyn Signer,
        now: u64,
    ) -> Result<bool, DepotError> {
        self.unlocked()?;
        let u = self
            .db
            .units
            .get(unit)
            .filter(|u| u.state == EnrolState::Activated)
            .ok_or_else(|| err(format!("unit {unit} is not waiting for approval")))?
            .clone();
        let doc = enrolment_digest(&self.cfg.site, &u)?;
        let mut set = match &u.approvals {
            Some(h) => {
                SignatureSet::parse(&robodr_seal::from_hex(h).unwrap_or_default()).map_err(fail)?
            }
            None => SignatureSet::empty(),
        };
        set.add(key, ENROLMENT_SIG_DOMAIN, &doc).map_err(fail)?;
        let signers = set
            .check(
                &self.site.trust,
                &[Role::Operator],
                ENROLMENT_SIG_DOMAIN,
                &doc,
            )
            .map_err(fail)?;
        let mut nu = u.clone();
        nu.approvals = Some(robodr_seal::to_hex(&set.to_bytes().map_err(fail)?));
        let done = signers.count(Role::Operator) >= self.operator_quorum(true);
        if done {
            let serial = self.db.cert_serial;
            self.db.cert_serial += 1;
            let identity: [u8; 65] = u
                .identity_public
                .as_deref()
                .and_then(robodr_seal::from_hex)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| err("identity key"))?;
            let ca_name = format!("{} depot unit CA", self.cfg.site);
            let der = x509::issue(
                &x509::Params {
                    issuer_cn: &ca_name,
                    subject_cn: unit,
                    subject_public: &identity,
                    serial,
                    not_before: now.saturating_sub(3600),
                    not_after: now + self.cfg.enrolment.cert_days * 86400,
                    kind: x509::Kind::Client,
                },
                &self.ca,
            )?;
            write_file(
                &self
                    .cfg
                    .state_dir
                    .join("units")
                    .join(unit)
                    .join("client.pem"),
                x509::pem("CERTIFICATE", &der).as_bytes(),
                0o644,
            )?;
            nu.state = EnrolState::Enrolled;
            nu.enrolled_at = Some(now);
            nu.cert_serial = Some(serial);
        }
        self.db.units.insert(unit.into(), nu);
        self.save()?;
        if done {
            self.finding(
                rules::UNIT_ENROLLED,
                Severity::Low,
                format!(
                    "unit {unit} enrolled (ring {}, attestation {:?})",
                    u.ring, u.attestation
                ),
                now,
            );
        }
        Ok(done)
    }

    /// The files a newly enrolled unit needs: its client certificate and
    /// the depot's CA certificate (`client.pem`, `depot-ca.pem` in `out`).
    pub fn enrol_export(&self, unit: &str, out: &Path) -> Result<(), DepotError> {
        let u = self
            .db
            .units
            .get(unit)
            .filter(|u| u.state == EnrolState::Enrolled)
            .ok_or_else(|| err(format!("unit {unit} is not enrolled")))?;
        std::fs::create_dir_all(out).map_err(|e| err(e.to_string()))?;
        for (from, to) in [
            (
                self.cfg
                    .state_dir
                    .join("units")
                    .join(&u.unit)
                    .join("client.pem"),
                "client.pem",
            ),
            (self.cfg.state_dir.join("tls/ca.pem"), "depot-ca.pem"),
        ] {
            std::fs::copy(&from, out.join(to))
                .map_err(|e| err(format!("{}: {e}", from.display())))?;
        }
        Ok(())
    }

    fn decision_quorum(
        &self,
        what: &str,
        subject: &str,
        n: u64,
        keys: &[&dyn Signer],
    ) -> Result<(), DepotError> {
        let doc = decision(&self.cfg.site, what, subject, n);
        let mut set = SignatureSet::empty();
        for k in keys {
            set.add(*k, DECISION_SIG_DOMAIN, &doc).map_err(fail)?;
        }
        let s = set
            .check(
                &self.site.trust,
                &[Role::Operator],
                DECISION_SIG_DOMAIN,
                &doc,
            )
            .map_err(fail)?;
        s.require(Role::Operator, self.operator_quorum(true), what)
            .map_err(fail)
    }

    /// Revoke a unit (operator quorum): it is served nothing more, no key
    /// is wrapped to it, its stages are recomputed without it.
    pub fn revoke(&mut self, unit: &str, keys: &[&dyn Signer]) -> Result<(), DepotError> {
        self.unlocked()?;
        self.decision_quorum("revoke", unit, 0, keys)?;
        let u = self
            .db
            .units
            .get_mut(unit)
            .ok_or_else(|| err(format!("no unit {unit}")))?;
        u.state = EnrolState::Revoked;
        self.save()
    }

    /// Re-anchor a locked database (operator quorum): accept it as it is,
    /// with the deployment sequence raised to at least `min_seq` (the
    /// highest a unit or the black box has seen, so no sequence number is
    /// ever reused).
    pub fn reanchor(&mut self, min_seq: u64, keys: &[&dyn Signer]) -> Result<(), DepotError> {
        self.decision_quorum("reanchor", "depot", min_seq, keys)?;
        if let Some(a) = &self.store.anchor {
            use robodr_seal::tpm_ident::Counter;
            self.db.nv = match a.tpm.counter(a.index).map_err(fail)? {
                Counter::Value(t) => Some(t),
                _ => None,
            };
        }
        self.db.locked = None;
        self.db.deployment_seq = self.db.deployment_seq.max(min_seq);
        self.save()
    }

    // ---------------------------------------------------------- rollouts --

    /// Create a rollout of `items` (RPK digests) over `stages` and its
    /// first stage's deployment (signed by the depot, waiting for
    /// operators). Stages are rings in ascending order, starting at `lab`
    /// or `canary`; a production ring needs a `canary` stage before it.
    pub fn rollout_create(
        &mut self,
        id: &str,
        items: &[String],
        stages: &[String],
        p: &RolloutParams,
        now: u64,
    ) -> Result<u64, DepotError> {
        self.unlocked()?;
        if !is_label(id) || self.db.rollouts.contains_key(id) {
            return Err(err("rollout id must be a new label"));
        }
        if items.is_empty() || items.len() > deployment::MAX_ITEMS {
            return Err(err("1..=256 items"));
        }
        let mut names = BTreeSet::new();
        for d in items {
            let r = self
                .db
                .rpks
                .get(d)
                .ok_or_else(|| err(format!("RPK {d} was not imported")))?;
            if !names.insert(r.name.clone()) {
                return Err(err(format!("two items of package {}", r.name)));
            }
        }
        let ranks: Vec<u32> = stages
            .iter()
            .map(|s| ring_rank(s).ok_or_else(|| err(format!("stage {s:?} is not a ring"))))
            .collect::<Result<_, _>>()?;
        if ranks.is_empty() || ranks.windows(2).any(|w| w[0] >= w[1]) {
            return Err(err(
                "stages must be rings in ascending order (lab, canary, ring-1, ...)",
            ));
        }
        if ranks[0] > 1 {
            return Err(err("a rollout starts at lab or canary"));
        }
        if ranks.iter().any(|r| *r > 1) && !stages.iter().any(|s| s == "canary") {
            return Err(err("a production ring needs a canary stage before it"));
        }
        if p.batch_size == 0
            || p.soak_s > deployment::MAX_SOAK_S
            || p.validity_s == 0
            || p.validity_s > deployment::MAX_VALIDITY_S
        {
            return Err(err("bad rollout parameters"));
        }
        self.db.rollouts.insert(
            id.into(),
            Rollout {
                id: id.into(),
                items: items.to_vec(),
                stages: stages.to_vec(),
                stage: 0,
                state: RolloutState::Running,
                batch_size: p.batch_size,
                soak_s: p.soak_s,
                max_failures: p.max_failures,
                validity_s: p.validity_s,
                maintenance_window: p.maintenance_window.clone(),
                units: p.units.clone(),
                deployments: Vec::new(),
                failures: BTreeMap::new(),
                halted_reason: None,
                created_at: now,
            },
        );
        match self.stage_deployment(id, now) {
            Ok(seq) => Ok(seq),
            Err(e) => {
                self.db.rollouts.remove(id);
                Err(e)
            }
        }
    }

    fn manifest_of(&self, digest: &str) -> Result<robodr_pkg::rpk::Manifest, DepotError> {
        let r = self.db.rpks.get(digest).ok_or_else(|| err("unknown RPK"))?;
        let p = self
            .bundle_dir(&r.bundle)
            .join(&r.dir)
            .join(robodr_pkg::rpk::MANIFEST_FILE);
        let b = robodr_release::fsio::read_capped(&p, robodr_pkg::rpk::MAX_MANIFEST_BYTES)
            .map_err(fail)?;
        if robodr_pkg::rpk::rpk_digest(&b) != digest {
            return Err(err("stored manifest does not match its digest"));
        }
        robodr_pkg::rpk::parse_manifest(&b).map_err(fail)
    }

    /// The enrolled units of `ring` (the trust file's assignment), within
    /// the rollout's `only` units.
    fn stage_units(&self, ring: &str, only: Option<&Vec<String>>) -> Vec<String> {
        let mut v: Vec<String> = self
            .db
            .units
            .values()
            .filter(|u| {
                u.state == EnrolState::Enrolled
                    && !u.erased
                    && self.site.ring_of_unit(&u.unit) == Some(ring)
                    && only.is_none_or(|o| o.contains(&u.unit))
            })
            .map(|u| u.unit.clone())
            .collect();
        v.sort();
        v
    }

    /// Make (sign) the deployment of a rollout's current stage.
    fn stage_deployment(&mut self, id: &str, now: u64) -> Result<u64, DepotError> {
        let r = self
            .db
            .rollouts
            .get(id)
            .ok_or_else(|| err("no rollout"))?
            .clone();
        let ring = r.stages[r.stage].clone();
        let units = self.stage_units(&ring, r.units.as_ref());
        if units.is_empty() || units.len() > MAX_STAGE_UNITS {
            return Err(err(format!("ring {ring} has no enrolled unit")));
        }
        if ring == "canary" && units.len() != 1 {
            return Err(err("the canary ring must hold exactly one enrolled unit"));
        }
        let mut items = Vec::new();
        let mut wraps = Vec::new();
        for d in &r.items {
            let rp = self
                .db
                .rpks
                .get(d)
                .ok_or_else(|| err("unknown RPK"))?
                .clone();
            items.push(Item {
                rpk_digest: d.clone(),
                name: rp.name.clone(),
                serial: rp.serial,
            });
            if rp.sealed {
                let m = self.manifest_of(d)?;
                for un in &units {
                    let u = &self.db.units[un];
                    let rec = u.record.as_ref().ok_or_else(|| err("no unit record"))?;
                    if u.attestation != Attestation::Verified
                        && !self.cfg.enrolment.allow_without_tpm
                    {
                        return Err(err(format!("unit {un} is not attested")));
                    }
                    let w =
                        robodr_seal::rpk::rewrap_for_unit(&self.wrap, &m, d, rec).map_err(fail)?;
                    wraps.push(w);
                }
            }
        }
        items.sort_by(|a, b| a.name.cmp(&b.name));
        wraps.sort_by(|a: &WrappedKey, b| (&a.unit, &a.rpk_digest).cmp(&(&b.unit, &b.rpk_digest)));
        let seq = self.db.deployment_seq + 1;
        let n = units.len() as u32;
        let doc = Deployment {
            format: DEPLOYMENT_FORMAT.into(),
            deployment_id: format!("{id}-s{}", r.stage),
            site: self.cfg.site.clone(),
            deployment_seq: seq,
            created_at: now,
            targets: Targets {
                units: units.clone(),
                groups: vec![],
            },
            ring: ring.clone(),
            items,
            not_before: now.saturating_sub(60),
            expires_at: now + r.validity_s,
            rollout: DocRollout {
                // 13b requirement 3: capped against the ring.
                batch_size: r.batch_size.min(n),
                soak_s: r.soak_s,
                max_failures: r.max_failures.min(n.saturating_sub(1)),
            },
            maintenance_window: r.maintenance_window.clone(),
            wrapped_keys: wraps,
        };
        doc.validate().map_err(fail)?;
        let bytes = to_canonical(&doc).map_err(fail)?;
        let mut set = SignatureSet::empty();
        set.add(self.signing.as_ref(), DEPLOYMENT_SIG_DOMAIN, &bytes)
            .map_err(fail)?;
        let path = self.deployment_path(seq);
        write_file(&path, &bytes, 0o644)?;
        write_file(&ops::sig_path(&path), &set.to_bytes().map_err(fail)?, 0o644)?;
        self.db.deployment_seq = seq;
        self.db.deployments.insert(
            seq,
            DbDeployment {
                seq,
                id: doc.deployment_id.clone(),
                rollout: id.into(),
                ring,
                units,
                state: DeployState::AwaitingApproval,
                created_at: now,
                activated_at: None,
                digest: deployment::deployment_digest(&bytes),
            },
        );
        if let Some(r) = self.db.rollouts.get_mut(id) {
            r.deployments.push(seq);
            r.failures.clear();
        }
        self.save()?;
        Ok(seq)
    }

    pub fn deployment_path(&self, seq: u64) -> PathBuf {
        self.cfg
            .state_dir
            .join("deployments")
            .join(format!("{seq:012}.json"))
    }

    /// An operator approves (signs) a deployment waiting for approval;
    /// once it verifies with the quorum of its ring it is active (served).
    pub fn deploy_approve(
        &mut self,
        seq: u64,
        key: &dyn Signer,
        now: u64,
    ) -> Result<bool, DepotError> {
        self.unlocked()?;
        let d = self
            .db
            .deployments
            .get(&seq)
            .filter(|d| d.state == DeployState::AwaitingApproval)
            .ok_or_else(|| err(format!("deployment {seq} is not waiting for approval")))?
            .clone();
        let path = self.deployment_path(seq);
        let bytes = std::fs::read(&path).map_err(|e| err(e.to_string()))?;
        if deployment::deployment_digest(&bytes) != d.digest {
            return Err(err("the stored deployment changed"));
        }
        let sp = ops::sig_path(&path);
        let mut set = SignatureSet::parse(&std::fs::read(&sp).map_err(|e| err(e.to_string()))?)
            .map_err(fail)?;
        set.add(key, DEPLOYMENT_SIG_DOMAIN, &bytes).map_err(fail)?;
        set.check(
            &self.site.trust,
            &[Role::Depot, Role::Operator],
            DEPLOYMENT_SIG_DOMAIN,
            &bytes,
        )
        .map_err(fail)?;
        let sb = set.to_bytes().map_err(fail)?;
        write_file(&sp, &sb, 0o644)?;
        let active = deployment::verify_deployment(&bytes, &sb, &self.site.trust, now).is_ok();
        if active {
            // Each unit is served the newest active deployment naming it
            // ([`Depot::deployment_for`]); older ones stay for the others.
            if let Some(x) = self.db.deployments.get_mut(&seq) {
                x.state = DeployState::Active;
                x.activated_at = Some(now);
            }
        }
        self.save()?;
        Ok(active)
    }

    /// Whether the rollout's current stage passed: active, every unit of
    /// it reported every item installed and healthy, and reported so again
    /// at least `soak_s` after the first such report; no failure.
    pub fn stage_passed(&self, id: &str, now: u64) -> Result<(), String> {
        let r = self.db.rollouts.get(id).ok_or("no rollout")?;
        if r.state != RolloutState::Running {
            return Err(format!("rollout is {:?}", r.state));
        }
        let seq = *r.deployments.last().ok_or("no deployment")?;
        let d = &self.db.deployments[&seq];
        if d.state != DeployState::Active {
            return Err(format!("stage deployment {seq} is {:?}", d.state));
        }
        if !r.failures.is_empty() {
            return Err(format!("failures: {:?}", r.failures));
        }
        for un in &d.units {
            let u = &self.db.units[un];
            let lr = u.last_report.as_ref().ok_or(format!("{un}: no report"))?;
            let rep = &lr.report;
            if rep.deployment_seq != seq {
                return Err(format!("{un}: has not taken deployment {seq}"));
            }
            for digest in &r.items {
                let ok = rep
                    .installed
                    .iter()
                    .any(|i| &i.rpk_digest == digest && i.healthy);
                if !ok {
                    return Err(format!("{un}: {digest} not installed and healthy"));
                }
            }
            let since = self
                .installed_since(un, seq)
                .ok_or(format!("{un}: not installed"))?;
            if lr.received_at < since + u64::from(r.soak_s) || now < since + u64::from(r.soak_s) {
                return Err(format!(
                    "{un}: soaking until {} (needs a report after it)",
                    since + u64::from(r.soak_s)
                ));
            }
        }
        Ok(())
    }

    fn installed_since(&self, unit: &str, seq: u64) -> Option<u64> {
        let p = self
            .cfg
            .state_dir
            .join("units")
            .join(unit)
            .join(format!("installed-{seq}"));
        std::fs::read_to_string(p).ok()?.trim().parse().ok()
    }

    /// Advance a rollout to its next stage, only when the current one
    /// passed ([`Depot::stage_passed`]): no ring is ever skipped.
    pub fn rollout_advance(&mut self, id: &str, now: u64) -> Result<Option<u64>, DepotError> {
        self.unlocked()?;
        self.stage_passed(id, now)
            .map_err(|w| err(format!("stage not passed: {w}")))?;
        let done = {
            let r = self
                .db
                .rollouts
                .get_mut(id)
                .ok_or_else(|| err("no rollout"))?;
            r.stage += 1;
            r.stage >= r.stages.len()
        };
        if done {
            if let Some(r) = self.db.rollouts.get_mut(id) {
                r.state = RolloutState::Completed;
            }
            self.save()?;
            return Ok(None);
        }
        self.stage_deployment(id, now).map(Some)
    }

    /// Resume a halted rollout (operator quorum): its stage is deployed
    /// again under a new sequence number (operators approve it again).
    pub fn rollout_resume(
        &mut self,
        id: &str,
        keys: &[&dyn Signer],
        now: u64,
    ) -> Result<u64, DepotError> {
        self.unlocked()?;
        let r = self.db.rollouts.get(id).ok_or_else(|| err("no rollout"))?;
        if r.state != RolloutState::Halted {
            return Err(err("rollout is not halted"));
        }
        let n = *r.deployments.last().unwrap_or(&0);
        self.decision_quorum("resume", id, n, keys)?;
        if let Some(r) = self.db.rollouts.get_mut(id) {
            r.state = RolloutState::Running;
            r.halted_reason = None;
        }
        self.stage_deployment(id, now)
    }

    /// Abort a rollout (operator quorum): nothing of it is served.
    pub fn rollout_abort(&mut self, id: &str, keys: &[&dyn Signer]) -> Result<(), DepotError> {
        self.unlocked()?;
        let r = self
            .db
            .rollouts
            .get(id)
            .ok_or_else(|| err("no rollout"))?
            .clone();
        self.decision_quorum("abort", id, *r.deployments.last().unwrap_or(&0), keys)?;
        for s in &r.deployments {
            if let Some(d) = self.db.deployments.get_mut(s) {
                if d.state != DeployState::Superseded {
                    d.state = DeployState::Halted;
                }
            }
        }
        if let Some(r) = self.db.rollouts.get_mut(id) {
            r.state = RolloutState::Aborted;
        }
        self.save()
    }

    // ----------------------------------------------------------- reports --

    /// Accept a signed unit report (`tls_unit`: the unit whose identity
    /// key the TLS client presented; `None` for a report from media).
    /// Judges the rollout (halt on failure) and returns a lease when the
    /// site uses leases.
    pub fn accept_report(
        &mut self,
        tls_unit: Option<&str>,
        bytes: &[u8],
        now: u64,
    ) -> Result<Option<robodr_seal::lease::Lease>, DepotError> {
        self.unlocked()?;
        let (claimed, _) = robodr_seal::report::parse_unverified(bytes).map_err(fail)?;
        if let Some(t) = tls_unit {
            if t != claimed.unit {
                return Err(err(format!(
                    "unit {t} sent a report signed as {}",
                    claimed.unit
                )));
            }
        }
        let u = self
            .db
            .units
            .get(&claimed.unit)
            .filter(|u| matches!(u.state, EnrolState::Enrolled))
            .ok_or_else(|| err(format!("unit {} is not enrolled", claimed.unit)))?
            .clone();
        let identity: [u8; 65] = u
            .identity_public
            .as_deref()
            .and_then(robodr_seal::from_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err("identity key"))?;
        let rep = robodr_seal::report::verify(bytes, &identity).map_err(fail)?;
        if rep.site != self.cfg.site {
            return Err(err("report of another site"));
        }
        let tpm = u.attestation == Attestation::Verified;
        if let Some(l) = &u.last_report {
            let newer = if tpm {
                (rep.tpm_resets, rep.tpm_clock) > (l.tpm_resets, l.tpm_clock)
            } else {
                rep.reported_at > l.reported_at
            };
            if !newer {
                return Err(err(format!(
                    "report of {} is not newer than the last one accepted (replay)",
                    rep.unit
                )));
            }
        }
        // Evidence.
        let ev = self
            .cfg
            .state_dir
            .join("units")
            .join(&rep.unit)
            .join("reports")
            .join(format!("{:010}-{:016}.json", rep.tpm_resets, rep.tpm_clock));
        write_file(&ev, bytes, 0o644)?;
        let mut halt: Option<(String, String)> = None;
        if let Some(d) = self.db.deployments.get(&rep.deployment_seq).cloned() {
            if d.units.contains(&rep.unit)
                && rep.deployment_digest.as_deref() == Some(d.digest.as_str())
            {
                let r = self.db.rollouts.get(&d.rollout).cloned();
                if let Some(r) = r {
                    let mine: Vec<_> = rep
                        .items
                        .iter()
                        .filter(|i| r.items.contains(&i.rpk_digest))
                        .collect();
                    let failed: Vec<String> = mine
                        .iter()
                        .filter(|i| {
                            matches!(
                                i.status,
                                robodr_seal::report::ItemState::Failed
                                    | robodr_seal::report::ItemState::Refused
                            )
                        })
                        .map(|i| format!("{} {} {:?}", i.name, i.serial, i.status))
                        .collect();
                    let all_ok = !mine.is_empty()
                        && r.items.iter().all(|dg| {
                            rep.installed
                                .iter()
                                .any(|x| &x.rpk_digest == dg && x.healthy)
                        });
                    if all_ok && self.installed_since(&rep.unit, d.seq).is_none() {
                        write_file(
                            &self
                                .cfg
                                .state_dir
                                .join("units")
                                .join(&rep.unit)
                                .join(format!("installed-{}", d.seq)),
                            now.to_string().as_bytes(),
                            0o644,
                        )?;
                    }
                    if !failed.is_empty()
                        && d.state == DeployState::Active
                        && r.state == RolloutState::Running
                        && *r.deployments.last().unwrap_or(&0) == d.seq
                    {
                        let rr = self
                            .db
                            .rollouts
                            .get_mut(&d.rollout)
                            .ok_or_else(|| err("rollout"))?;
                        rr.failures.insert(rep.unit.clone(), failed.join(", "));
                        let cap = rr
                            .max_failures
                            .min((d.units.len() as u32).saturating_sub(1));
                        if rr.failures.len() as u32 > cap {
                            rr.state = RolloutState::Halted;
                            let why = format!(
                                "stage {} ({}) failed on {}: {}",
                                rr.stage,
                                d.ring,
                                rep.unit,
                                failed.join(", ")
                            );
                            rr.halted_reason = Some(why.clone());
                            halt = Some((d.rollout.clone(), why));
                            if let Some(x) = self.db.deployments.get_mut(&d.seq) {
                                x.state = DeployState::Halted;
                            }
                        }
                    }
                }
            }
        }
        let mut lease = None;
        if let Some(uu) = self.db.units.get_mut(&rep.unit) {
            uu.erased = rep.erased;
            uu.last_report = Some(LastReport {
                received_at: now,
                tpm_resets: rep.tpm_resets,
                tpm_clock: rep.tpm_clock,
                reported_at: rep.reported_at,
                deployment_seq: rep.deployment_seq,
                report: rep.clone(),
            });
            let gated = uu
                .record
                .as_ref()
                .and_then(|r| r.tpm.as_ref())
                .is_some_and(|t| t.lease_key.is_some());
            if let (Some(cfg), Some(key), true, false) =
                (&self.cfg.lease, &self.lease_key, gated, rep.erased)
            {
                let rec = uu
                    .record
                    .as_ref()
                    .and_then(|r| r.tpm.as_ref())
                    .ok_or_else(|| err("record"))?;
                let aname = robodr_seal::from_hex(&rec.policy_authority_name)
                    .ok_or_else(|| err("authority name"))?;
                uu.lease_seq += 1;
                let l = robodr_seal::lease::issue(
                    &robodr_seal::lease::LeaseGrant {
                        site: &self.cfg.site,
                        unit: &rep.unit,
                        platform: uu.platform.as_deref().unwrap_or_default(),
                        authority_name: &aname,
                        lease_seq: uu.lease_seq,
                        issued_at: now,
                        now: robodr_seal::lease::TpmTime {
                            clock: rep.tpm_clock,
                            reset_count: rep.tpm_resets,
                            restart_count: 0,
                            safe: true,
                        },
                        lifetime_ms: cfg.lifetime_s * 1000,
                        reboots: cfg.reboots,
                    },
                    key,
                )
                .map_err(fail)?;
                write_file(
                    &self
                        .cfg
                        .state_dir
                        .join("units")
                        .join(&rep.unit)
                        .join("lease.json"),
                    &l.to_bytes().map_err(fail)?,
                    0o644,
                )?;
                lease = Some(l);
            }
        }
        self.save()?;
        if let Some((rollout, why)) = halt {
            self.finding(
                rules::ROLLOUT_HALTED,
                Severity::High,
                format!("rollout {rollout} halted: {why}"),
                now,
            );
        }
        Ok(lease)
    }

    // ------------------------------------------------------------- packs --

    /// The newest active deployment that targets `unit`.
    pub fn deployment_for(&self, unit: &str) -> Option<&DbDeployment> {
        self.db
            .deployments
            .values()
            .rev()
            .find(|d| d.state == DeployState::Active && d.units.iter().any(|u| u == unit))
    }

    /// The files of `unit`'s media pack: `(path in the pack, file)`.
    /// Refused for a unit that is not enrolled, revoked or erased, or has
    /// no active deployment.
    pub fn pack_files(&self, unit: &str) -> Result<Vec<(String, PathBuf)>, DepotError> {
        self.unlocked()?;
        let u = self
            .db
            .units
            .get(unit)
            .filter(|u| u.state == EnrolState::Enrolled && !u.erased)
            .ok_or_else(|| err(format!("unit {unit} is not an enrolled unit")))?;
        let d = self
            .deployment_for(&u.unit)
            .ok_or_else(|| err(format!("no active deployment for {unit}")))?;
        let a = self.cfg.anchor_path();
        let dp = self.deployment_path(d.seq);
        let mut out = vec![
            ("trust.json".to_string(), a.clone()),
            ("trust.json.sig".to_string(), ops::sig_path(&a)),
            ("deployment.json".to_string(), dp.clone()),
            ("deployment.json.sig".to_string(), ops::sig_path(&dp)),
        ];
        let lease = self
            .cfg
            .state_dir
            .join("units")
            .join(unit)
            .join("lease.json");
        if lease.exists() {
            out.push(("lease.json".into(), lease));
        }
        let r = &self.db.rollouts[&d.rollout];
        let labels: BTreeSet<&String> = r
            .items
            .iter()
            .filter_map(|dg| self.db.rpks.get(dg).map(|x| &x.bundle))
            .collect();
        for (i, label) in labels.iter().enumerate() {
            let dir = self.bundle_dir(label);
            let bb = std::fs::read(dir.join(robodr_pkg::bundle::BUNDLE_FILE))
                .map_err(|e| err(e.to_string()))?;
            let m = robodr_pkg::bundle::parse_bundle(&bb).map_err(fail)?;
            let l = format!("b{i}");
            for f in [
                robodr_pkg::bundle::BUNDLE_FILE,
                robodr_pkg::bundle::BUNDLE_SIG_FILE,
            ] {
                out.push((format!("bundles/{l}/{f}"), dir.join(f)));
            }
            for f in &m.files {
                out.push((format!("bundles/{l}/{}", f.path), dir.join(&f.path)));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Write `unit`'s media pack to `out` (which must not exist).
    pub fn write_pack(&self, unit: &str, out: &Path) -> Result<usize, DepotError> {
        if out.exists() {
            return Err(err(format!("{} exists", out.display())));
        }
        let files = self.pack_files(unit)?;
        for (rel, from) in &files {
            let to = out.join(rel);
            if let Some(p) = to.parent() {
                std::fs::create_dir_all(p).map_err(|e| err(e.to_string()))?;
            }
            std::fs::copy(from, &to).map_err(|e| err(format!("{}: {e}", from.display())))?;
        }
        Ok(files.len())
    }

    /// The unit whose enrolled identity key is `spki` (DER), if enrolled.
    pub fn unit_of_spki(&self, spki: &[u8]) -> Option<String> {
        self.db
            .units
            .values()
            .filter(|u| u.state == EnrolState::Enrolled)
            .find(|u| {
                u.identity_public
                    .as_deref()
                    .and_then(robodr_seal::from_hex)
                    .and_then(|b| <[u8; 65]>::try_from(b).ok())
                    .is_some_and(|p| robodr_seal::keys::p256_spki_der(&p) == spki)
            })
            .map(|u| u.unit.clone())
    }

    /// A short inventory (§4.3).
    pub fn inventory(&self) -> serde_json::Value {
        let units: Vec<serde_json::Value> = self
            .db
            .units
            .values()
            .map(|u| {
                serde_json::json!({
                    "unit": u.unit, "ring": u.ring, "state": u.state,
                    "attestation": u.attestation, "platform": u.platform,
                    "installed": u.last_report.as_ref().map(|r| &r.report.installed),
                    "deployment_seq": u.last_report.as_ref().map(|r| r.deployment_seq),
                    "last_report": u.last_report.as_ref().map(|r| r.received_at),
                    "erased": u.erased,
                })
            })
            .collect();
        serde_json::json!({
            "site": self.cfg.site,
            "generation": self.db.generation,
            "locked": self.db.locked,
            "units": units,
            "rollouts": self.db.rollouts,
            "deployments": self.db.deployments,
        })
    }
}
