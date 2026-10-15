//! Module configuration (`[module.robodr-sensor-ros2]` in `pulsar.toml`) and
//! its validation. Pulsar-independent: only `std` + `serde`.
//!
//! Pulsar deserialises the section with `serde` (`ModuleConfig::parse`, via
//! `serde_ignored`, so unknown keys are warned about, not rejected). The
//! `enabled` key is consumed by Pulsar itself and never reaches this struct.
//!
//! Every field has a default, so a missing section parses cleanly; this
//! matters because the module is `DEFAULT_ENABLED = false` and Pulsar parses
//! the config of disabled modules too.
//!
//! ## Port computation
//!
//! DDSI-RTPS 2.2 §9.6.1.1 well-known ports: the SPDP multicast port is
//! `PB + DG * domainId + d0` with `PB = 7400`, `DG = 250`, `d0 = 0`. The
//! largest domain whose port still fits in a `u16` is 232. ROS 2 documents
//! 0..=101 as the safe range on Linux (higher domains can collide with the
//! ephemeral port range for participant unicast ports), plus 215..=232; other
//! values are accepted with a warning.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Deserialize;

pub const DEFAULT_PROFILE_PATH: &str = "/etc/robodr/profile.json";
pub const DEFAULT_SPDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 1);
pub const SPDP_PORT_BASE: u32 = 7400;
pub const SPDP_DOMAIN_GAIN: u32 = 250;
pub const MAX_DOMAIN_ID: u32 = 232;
pub const DEFAULT_DEDUP_CAPACITY: usize = 4096;
pub const MAX_DEDUP_CAPACITY: usize = 1 << 20;

/// Raw config block as written by the operator.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Absolute path to the model profile (JSON). See `config/profile.example.json`.
    pub profile_path: PathBuf,
    /// RTPS / ROS 2 domain id (`ROS_DOMAIN_ID`). Determines the SPDP port.
    pub domain_id: u32,
    /// Explicit SPDP port, overriding the domain-derived one. Only for DDS
    /// deployments with non-standard port parameters.
    pub spdp_port: Option<u16>,
    /// SPDP multicast group. DDS default is 239.255.0.1.
    pub spdp_group: Ipv4Addr,
    /// Local interface address to join the group on (0.0.0.0 = kernel's choice).
    pub interface: Ipv4Addr,
    /// Listen on the SPDP multicast socket. Set to false only when all
    /// datagrams come from an external source (e.g. `robodr-capture`).
    pub listen_spdp: bool,
    /// Max distinct deviations remembered for dedup.
    pub dedup_capacity: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile_path: PathBuf::from(DEFAULT_PROFILE_PATH),
            domain_id: 0,
            spdp_port: None,
            spdp_group: DEFAULT_SPDP_GROUP,
            interface: Ipv4Addr::UNSPECIFIED,
            listen_spdp: true,
            dedup_capacity: DEFAULT_DEDUP_CAPACITY,
        }
    }
}

/// Where and how to listen for SPDP multicast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdpSettings {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: Ipv4Addr,
}

/// Validated, ready-to-use settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub profile_path: PathBuf,
    pub domain_id: u32,
    /// `None` when `listen_spdp = false`.
    pub spdp: Option<SpdpSettings>,
    pub dedup_capacity: usize,
}

/// SPDP multicast port for a domain, or `None` if the domain is out of range.
pub fn spdp_multicast_port(domain_id: u32) -> Option<u16> {
    if domain_id > MAX_DOMAIN_ID {
        return None;
    }
    u16::try_from(SPDP_PORT_BASE + SPDP_DOMAIN_GAIN * domain_id).ok()
}

impl Config {
    /// Validate and resolve. `Ok` carries the settings plus non-fatal
    /// warnings to log; `Err` is a message suitable for a `ModuleError`.
    pub fn validate(&self) -> Result<(Settings, Vec<String>), String> {
        let mut warnings = Vec::new();

        if self.profile_path.as_os_str().is_empty() {
            return Err("profile_path is empty".into());
        }
        if !self.profile_path.is_absolute() {
            return Err(format!(
                "profile_path must be absolute (the daemon's working directory is not \
                 defined): {}",
                self.profile_path.display()
            ));
        }

        let Some(derived_port) = spdp_multicast_port(self.domain_id) else {
            return Err(format!(
                "domain_id {} out of range: must be 0..={MAX_DOMAIN_ID} \
                 (port = {SPDP_PORT_BASE} + {SPDP_DOMAIN_GAIN} * domain_id must fit in 16 bits)",
                self.domain_id
            ));
        };
        if (102..=214).contains(&self.domain_id) {
            warnings.push(format!(
                "domain_id {} is outside the ROS 2 recommended ranges 0..=101 and 215..=232",
                self.domain_id
            ));
        }

        if self.dedup_capacity == 0 || self.dedup_capacity > MAX_DEDUP_CAPACITY {
            return Err(format!(
                "dedup_capacity {} out of range: must be 1..={MAX_DEDUP_CAPACITY}",
                self.dedup_capacity
            ));
        }

        let spdp = if self.listen_spdp {
            let port = match self.spdp_port {
                Some(0) => return Err("spdp_port must not be 0".into()),
                Some(p) if p != derived_port => {
                    warnings.push(format!(
                        "spdp_port {p} overrides the port derived from domain_id {} ({derived_port})",
                        self.domain_id
                    ));
                    p
                }
                Some(p) => p,
                None => derived_port,
            };
            if !self.spdp_group.is_multicast() {
                return Err(format!(
                    "spdp_group {} is not an IPv4 multicast address",
                    self.spdp_group
                ));
            }
            if self.interface.is_multicast() || self.interface.is_broadcast() {
                return Err(format!(
                    "interface {} must be a unicast local address or 0.0.0.0",
                    self.interface
                ));
            }
            Some(SpdpSettings {
                group: self.spdp_group,
                port,
                interface: self.interface,
            })
        } else {
            if self.spdp_port.is_some() {
                warnings.push("spdp_port is ignored because listen_spdp = false".into());
            }
            None
        };

        Ok((
            Settings {
                profile_path: self.profile_path.clone(),
                domain_id: self.domain_id,
                spdp,
                dedup_capacity: self.dedup_capacity,
            },
            warnings,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pulsar parses TOML; `toml` is not a dependency of this crate, so these
    // tests drive the same serde derive through JSON.
    fn parse(json: &str) -> Config {
        serde_json::from_str(json).expect("config should parse")
    }

    #[test]
    fn port_formula() {
        assert_eq!(spdp_multicast_port(0), Some(7400));
        assert_eq!(spdp_multicast_port(1), Some(7650));
        assert_eq!(spdp_multicast_port(42), Some(17900));
        assert_eq!(spdp_multicast_port(232), Some(65400));
        assert_eq!(spdp_multicast_port(233), None);
        assert_eq!(spdp_multicast_port(u32::MAX), None);
    }

    #[test]
    fn empty_section_is_valid_defaults() {
        let c = parse("{}");
        assert_eq!(c, Config::default());
        let (s, w) = c.validate().unwrap();
        assert!(w.is_empty());
        assert_eq!(s.profile_path, PathBuf::from(DEFAULT_PROFILE_PATH));
        assert_eq!(
            s.spdp,
            Some(SpdpSettings {
                group: DEFAULT_SPDP_GROUP,
                port: 7400,
                interface: Ipv4Addr::UNSPECIFIED,
            })
        );
        assert_eq!(s.dedup_capacity, DEFAULT_DEDUP_CAPACITY);
    }

    #[test]
    fn domain_id_sets_port() {
        let (s, w) = parse(r#"{"domain_id": 7}"#).validate().unwrap();
        assert_eq!(s.spdp.unwrap().port, 7400 + 250 * 7);
        assert!(w.is_empty());
    }

    #[test]
    fn domain_out_of_range_is_rejected() {
        let e = parse(r#"{"domain_id": 233}"#).validate().unwrap_err();
        assert!(e.contains("domain_id 233"));
    }

    #[test]
    fn domain_outside_ros_range_warns() {
        let (s, w) = parse(r#"{"domain_id": 150}"#).validate().unwrap();
        assert_eq!(s.spdp.unwrap().port, 7400 + 250 * 150);
        assert_eq!(w.len(), 1);
        let (_, w) = parse(r#"{"domain_id": 220}"#).validate().unwrap();
        assert!(w.is_empty());
    }

    #[test]
    fn explicit_port_overrides_with_warning() {
        let (s, w) = parse(r#"{"domain_id": 1, "spdp_port": 7400}"#)
            .validate()
            .unwrap();
        assert_eq!(s.spdp.unwrap().port, 7400);
        assert_eq!(w.len(), 1);
        let (_, w) = parse(r#"{"domain_id": 1, "spdp_port": 7650}"#)
            .validate()
            .unwrap();
        assert!(w.is_empty());
        assert!(parse(r#"{"spdp_port": 0}"#).validate().is_err());
    }

    #[test]
    fn bad_addresses_are_rejected() {
        assert!(parse(r#"{"spdp_group": "10.0.0.1"}"#).validate().is_err());
        assert!(parse(r#"{"interface": "239.255.0.1"}"#).validate().is_err());
        assert!(parse(r#"{"interface": "255.255.255.255"}"#)
            .validate()
            .is_err());
        assert!(parse(r#"{"interface": "10.1.2.3"}"#).validate().is_ok());
    }

    #[test]
    fn unparseable_values_fail_at_parse_time() {
        assert!(serde_json::from_str::<Config>(r#"{"spdp_group": "not-an-ip"}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"domain_id": -1}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"spdp_port": 70000}"#).is_err());
    }

    #[test]
    fn profile_path_must_be_absolute_and_non_empty() {
        assert!(parse(r#"{"profile_path": ""}"#).validate().is_err());
        assert!(parse(r#"{"profile_path": "profile.json"}"#)
            .validate()
            .is_err());
        assert!(parse(r#"{"profile_path": "/srv/p.json"}"#)
            .validate()
            .is_ok());
    }

    #[test]
    fn dedup_capacity_bounds() {
        assert!(parse(r#"{"dedup_capacity": 0}"#).validate().is_err());
        assert!(parse(r#"{"dedup_capacity": 1}"#).validate().is_ok());
        let too_big = format!(r#"{{"dedup_capacity": {}}}"#, MAX_DEDUP_CAPACITY + 1);
        assert!(parse(&too_big).validate().is_err());
    }

    #[test]
    fn spdp_can_be_disabled() {
        let (s, w) = parse(r#"{"listen_spdp": false}"#).validate().unwrap();
        assert!(s.spdp.is_none());
        assert!(w.is_empty());
        // A bad group does not matter when SPDP is off...
        assert!(parse(r#"{"listen_spdp": false, "spdp_group": "10.0.0.1"}"#)
            .validate()
            .is_ok());
        // ...but a stray port is called out.
        let (_, w) = parse(r#"{"listen_spdp": false, "spdp_port": 7400}"#)
            .validate()
            .unwrap();
        assert_eq!(w.len(), 1);
    }
}
