//! The entry station's scan (`docs/SECURE-DELIVERY.md` §6.1, Sprint 14a):
//! verify a bundle completely (release quorum, every hash, every RPK, site
//! policy), read each RPK's CycloneDX SBOM, diff it against the previous
//! serial this station saw, match its components against an offline
//! vulnerability database carried in on the same media, and sign the
//! result (`robodr-entry-report/1`, [`robodr_pkg::entry`]) with the
//! station's entry key. `robodr-depot import` requires a passing report
//! for exactly that bundle.
//!
//! The station checks the bundle's chain only against the bundle's own
//! predecessor link (the depot holds the site's chain and checks it at
//! import); it keeps its own SBOM history (`history/<package>.json`).
//!
//! Vulnerability database (`robodr-vulndb/1`, JSON):
//! `{"format","name","version","entries":[{"id","component","versions":[..],"severity"}]}`;
//! a component matches an entry when its name is the entry's `component`
//! and its version is listed exactly. This is the contract with whatever
//! site tooling builds the database; it is not a vulnerability scanner.

use crate::{err, DepotError};
use robodr_pkg::entry::{
    EntryReport, RpkScan, SbomDiff, Severity, Verdict, Vuln, VulnDbRef, ENTRY_FORMAT,
    ENTRY_SIG_DOMAIN, MAX_REPORT_LIFETIME_S,
};
use robodr_release::ops::{verify_bundle_dir, ChainMode, SiteTrust};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const VULNDB_FORMAT: &str = "robodr-vulndb/1";
const MAX_VULNDB: usize = 64 * 1024 * 1024;
const MAX_SBOM: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnEntry {
    pub id: String,
    pub component: String,
    pub versions: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnDb {
    pub format: String,
    pub name: String,
    pub version: u64,
    pub entries: Vec<VulnEntry>,
}

/// SBOM history of one package at the station.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    serial: u64,
    /// `name@version` -> licence (`""` when none).
    components: BTreeMap<String, String>,
}

/// Components of a CycloneDX JSON SBOM: `name@version` -> licence.
pub fn sbom_components(b: &[u8]) -> Result<BTreeMap<String, String>, DepotError> {
    if b.len() > MAX_SBOM {
        return Err(err("SBOM too large"));
    }
    let v: serde_json::Value = serde_json::from_slice(b).map_err(|e| err(format!("SBOM: {e}")))?;
    if v.get("bomFormat").and_then(|x| x.as_str()) != Some("CycloneDX") {
        return Err(err("SBOM is not CycloneDX"));
    }
    let mut out = BTreeMap::new();
    let mut stack: Vec<&serde_json::Value> = v
        .get("components")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    while let Some(c) = stack.pop() {
        if out.len() > robodr_pkg::entry::MAX_COMPONENT_LIST {
            return Err(err("SBOM: too many components"));
        }
        let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let ver = c.get("version").and_then(|x| x.as_str()).unwrap_or("");
        if !name.is_empty() {
            let lic = c
                .get("licenses")
                .and_then(|l| l.as_array())
                .map(|l| {
                    let mut v: Vec<String> = l
                        .iter()
                        .filter_map(|e| {
                            e.get("expression")
                                .or_else(|| e.get("license").and_then(|x| x.get("id")))
                                .or_else(|| e.get("license").and_then(|x| x.get("name")))
                                .and_then(|x| x.as_str())
                                .map(str::to_string)
                        })
                        .collect();
                    v.sort();
                    v.join(" AND ")
                })
                .unwrap_or_default();
            out.insert(clean(&format!("{name}@{ver}")), clean(&lic));
        }
        if let Some(sub) = c.get("components").and_then(|x| x.as_array()) {
            stack.extend(sub.iter());
        }
    }
    Ok(out)
}

/// Printable ASCII only, at most 200 characters (the report's rule).
fn clean(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(robodr_pkg::entry::MAX_TEXT)
        .collect();
    if t.trim().is_empty() {
        "?".into()
    } else {
        t
    }
}

/// What the scan needs.
pub struct ScanInput<'a> {
    pub bundle: &'a Path,
    pub site: &'a SiteTrust,
    pub station: &'a str,
    pub vulndb: Option<&'a Path>,
    pub history: &'a Path,
    pub fail_on: Severity,
    pub now: u64,
    pub lifetime_s: u64,
}

/// Scan a bundle and return the (unsigned) report.
pub fn scan(i: &ScanInput<'_>) -> Result<EntryReport, DepotError> {
    let bb = std::fs::read(i.bundle.join(robodr_pkg::bundle::BUNDLE_FILE))
        .map_err(|e| err(format!("bundle.json: {e}")))?;
    let m = robodr_pkg::bundle::parse_bundle(&bb).map_err(|e| err(e.to_string()))?;
    let chain = match (&m.prev_bundle_hash, m.bundle_seq) {
        (Some(h), s) if s > 1 => ChainMode::After {
            seq: s - 1,
            hash: h.clone(),
        },
        _ => ChainMode::Genesis,
    };
    let rep = verify_bundle_dir(i.bundle, i.site, &chain, i.now).map_err(|e| err(e.to_string()))?;
    let db = match i.vulndb {
        Some(p) => {
            let b =
                robodr_release::fsio::read_capped(p, MAX_VULNDB).map_err(|e| err(e.to_string()))?;
            let d: VulnDb = serde_json::from_slice(&b).map_err(|e| err(format!("vulndb: {e}")))?;
            if d.format != VULNDB_FORMAT || !robodr_pkg::common::is_label(&d.name) {
                return Err(err("vulndb: unsupported format or bad name"));
            }
            Some((d, robodr_pkg::common::sha256_hex(&b)))
        }
        None => None,
    };
    std::fs::create_dir_all(i.history).map_err(|e| err(e.to_string()))?;
    let mut rpks = Vec::new();
    for v in &rep.rpks {
        let mf = &v.manifest;
        let entry = m
            .rpks
            .iter()
            .find(|e| e.digest == v.digest)
            .ok_or_else(|| err("RPK not in the bundle listing"))?;
        let sbom = match mf.sbom_entry() {
            None => None,
            Some(f) => {
                // The SBOM is a single clear chunk-set: reassemble it.
                let mut b = Vec::new();
                for c in &f.chunks {
                    let ch = &mf.chunks[*c as usize];
                    let p = i
                        .bundle
                        .join(&entry.dir)
                        .join(robodr_pkg::rpk::CHUNKS_DIR)
                        .join(&ch.sha256);
                    b.extend(
                        robodr_release::fsio::read_capped(&p, MAX_SBOM)
                            .map_err(|e| err(e.to_string()))?,
                    );
                }
                Some((f.sha256.clone(), sbom_components(&b)?))
            }
        };
        let hist_path = i.history.join(format!("{}.json", mf.name));
        let prev: Option<History> = std::fs::read(&hist_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .filter(|h: &History| h.serial < mf.version.serial);
        let mut vulns = BTreeSet::new();
        let diff = match &sbom {
            None => None,
            Some((sha, comps)) => {
                let (added, removed, lic) = match &prev {
                    None => (Vec::new(), Vec::new(), Vec::new()),
                    Some(p) => {
                        let added = comps
                            .keys()
                            .filter(|k| !p.components.contains_key(*k))
                            .cloned()
                            .collect();
                        let removed = p
                            .components
                            .keys()
                            .filter(|k| !comps.contains_key(*k))
                            .cloned()
                            .collect();
                        let lic = comps
                            .iter()
                            .filter_map(|(k, l)| {
                                p.components
                                    .get(k)
                                    .filter(|old| *old != l)
                                    .map(|old| clean(&format!("{k}: {old} -> {l}")))
                            })
                            .collect();
                        (added, removed, lic)
                    }
                };
                if let Some((d, _)) = &db {
                    for k in comps.keys() {
                        let (n, ver) = k.rsplit_once('@').unwrap_or((k.as_str(), ""));
                        for e in &d.entries {
                            if e.component == n && e.versions.iter().any(|x| x == ver) {
                                vulns.insert((clean(&e.id), k.clone(), e.severity));
                            }
                        }
                    }
                }
                Some(SbomDiff {
                    sha256: sha.clone(),
                    components: comps.len() as u64,
                    previous_serial: prev.as_ref().map(|p| p.serial),
                    added,
                    removed,
                    licence_changes: lic,
                })
            }
        };
        rpks.push(RpkScan {
            digest: v.digest.clone(),
            name: mf.name.clone(),
            serial: mf.version.serial,
            sbom: diff,
            vulnerabilities: vulns
                .into_iter()
                .map(|(id, component, severity)| Vuln {
                    id,
                    component,
                    severity,
                })
                .collect(),
        });
        if let Some((_, comps)) = sbom {
            let h = History {
                serial: mf.version.serial,
                components: comps,
            };
            let _ = std::fs::write(&hist_path, serde_json::to_vec(&h).unwrap_or_default());
        }
    }
    rpks.sort_by(|a, b| a.digest.cmp(&b.digest));
    let worst = rpks
        .iter()
        .flat_map(|r| r.vulnerabilities.iter().map(|v| v.severity))
        .max();
    let lifetime = i.lifetime_s.clamp(1, MAX_REPORT_LIFETIME_S);
    let r = EntryReport {
        format: ENTRY_FORMAT.into(),
        site: i.site.trust.file().site.clone(),
        station: i.station.into(),
        programme: m.programme.clone(),
        bundle_seq: m.bundle_seq,
        bundle_hash: rep.bundle.hash.clone(),
        scanned_at: i.now,
        expires_at: i.now + lifetime,
        vulndb: db.map(|(d, sha)| VulnDbRef {
            name: d.name,
            version: d.version,
            sha256: sha,
        }),
        rpks,
        fail_on: i.fail_on,
        verdict: if worst.is_some_and(|w| w >= i.fail_on) {
            Verdict::Fail
        } else {
            Verdict::Pass
        },
    };
    r.validate().map_err(|e| err(e.to_string()))?;
    Ok(r)
}

/// Sign a report with the station's entry key; `(report, sigset)` bytes.
pub fn sign(
    r: &EntryReport,
    key: &dyn robodr_blackbox::Signer,
) -> Result<(Vec<u8>, Vec<u8>), DepotError> {
    let b = robodr_pkg::common::to_canonical(r).map_err(|e| err(e.to_string()))?;
    let mut s = robodr_pkg::sig::SignatureSet::empty();
    s.add(key, ENTRY_SIG_DOMAIN, &b)
        .map_err(|e| err(e.to_string()))?;
    Ok((b, s.to_bytes().map_err(|e| err(e.to_string()))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclonedx_components() {
        let s = br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"libfoo","version":"1.2","licenses":[{"license":{"id":"MIT"}}]},
            {"name":"libbar","version":"0.9","components":[{"name":"inner","version":"1"}]}]}"#;
        let c = sbom_components(s).unwrap();
        assert_eq!(c.get("libfoo@1.2").map(String::as_str), Some("MIT"));
        assert!(c.contains_key("inner@1") && c.contains_key("libbar@0.9"));
        assert!(sbom_components(br#"{"bomFormat":"SPDX"}"#).is_err());
    }
}
