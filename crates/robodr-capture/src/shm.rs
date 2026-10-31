//! DDS shared-memory segments in `/dev/shm`: the host-side half of the
//! shared-memory blind spot (SALES-READINESS T14).
//!
//! A packet capture never sees DDS traffic that goes over shared memory
//! (see the crate docs, "Limits"). On the wire this shows as SPDP locators
//! of a shared-memory kind (`robodr_rtps::LocatorTransport::SharedMemory`);
//! on the host it shows as segments in `/dev/shm`, which this module
//! recognises by name:
//!
//! | name | stack |
//! |---|---|
//! | `fastrtps_port<N>`, `sem.fastrtps_port<N>_mutex` | Fast DDS SHM transport, one port per listening participant (seen on Fast DDS 2.6, ROS 2 Humble) |
//! | `fastrtps_<hex>` | Fast DDS SHM transport, a participant's segment |
//! | `fast_datasharing_*` | Fast DDS data sharing (zero copy) |
//! | `iceoryx_mgmt`, `iox_*`, `iox2_*` | Eclipse iceoryx (Cyclone DDS `SharedMemory`, RouDi) |
//!
//! `_el` (Fast DDS lock files) and other names are not counted. Connext
//! SHMEM uses System V shared memory and is not visible here.
//!
//! Read-only: only the directory listing is read (names, never contents),
//! bounded by [`MAX_ENTRIES`].

use std::io;
use std::path::Path;

/// Default shared-memory mount.
pub const DEV_SHM: &str = "/dev/shm";
/// Directory entries examined at most (a busy host has a few hundred).
pub const MAX_ENTRIES: usize = 65_536;

/// Which shared-memory transport a `/dev/shm` entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ShmKind {
    /// Fast DDS SHM transport (ports and participant segments).
    FastDdsShm,
    /// Fast DDS data sharing.
    FastDdsDataSharing,
    /// Eclipse iceoryx (Cyclone DDS shared memory).
    Iceoryx,
}

impl ShmKind {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::FastDdsShm => "Fast DDS shared-memory transport",
            Self::FastDdsDataSharing => "Fast DDS data sharing",
            Self::Iceoryx => "iceoryx (Cyclone DDS shared memory)",
        }
    }
}

/// Classify one `/dev/shm` entry name.
pub fn classify(name: &str) -> Option<ShmKind> {
    if name.ends_with("_el") {
        return None;
    }
    if name.starts_with("fast_datasharing_") {
        return Some(ShmKind::FastDdsDataSharing);
    }
    if name.starts_with("fastrtps_") || name.starts_with("sem.fastrtps_") {
        return Some(ShmKind::FastDdsShm);
    }
    if name == "iceoryx_mgmt" || name.starts_with("iox_") || name.starts_with("iox2_") {
        return Some(ShmKind::Iceoryx);
    }
    None
}

/// What a scan found: entries per kind (sorted by kind), and whether the
/// listing was cut at [`MAX_ENTRIES`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShmScan {
    pub found: Vec<(ShmKind, u64)>,
    pub truncated: bool,
}

impl ShmScan {
    /// No DDS shared-memory segment.
    pub fn is_empty(&self) -> bool {
        self.found.is_empty()
    }

    /// `"Fast DDS shared-memory transport (6)"`, comma separated.
    pub fn summary(&self) -> String {
        self.found
            .iter()
            .map(|(k, n)| format!("{} ({n})", k.name()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Count DDS shared-memory entries in the names of `names`.
pub fn scan_names<I, S>(names: I) -> ShmScan
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut scan = ShmScan::default();
    for (i, name) in names.into_iter().enumerate() {
        if i >= MAX_ENTRIES {
            scan.truncated = true;
            break;
        }
        let Some(kind) = classify(name.as_ref()) else {
            continue;
        };
        match scan.found.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => scan.found.push((kind, 1)),
        }
    }
    scan.found.sort_unstable();
    scan
}

/// Scan a directory (normally [`DEV_SHM`]). A missing directory is an
/// empty scan; names that are not UTF-8 are skipped.
pub fn scan_dir(dir: &Path) -> io::Result<ShmScan> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ShmScan::default()),
        Err(e) => return Err(e),
    };
    let names = rd
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok());
    Ok(scan_names(names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_real_fast_dds_2_6_names() {
        // `ls /dev/shm` of a ros:humble-ros-base container running two
        // rclpy nodes with Fast DDS default transports.
        let names = [
            "fastrtps_8919360421b22fc9",
            "fastrtps_8919360421b22fc9_el",
            "fastrtps_a944329f1b73fad3",
            "fastrtps_a944329f1b73fad3_el",
            "fastrtps_port7411",
            "fastrtps_port7411_el",
            "fastrtps_port7413",
            "fastrtps_port7413_el",
            "sem.fastrtps_port7411_mutex",
            "sem.fastrtps_port7413_mutex",
            "unrelated",
        ];
        let s = scan_names(names);
        assert_eq!(s.found, vec![(ShmKind::FastDdsShm, 6)]);
        assert!(!s.truncated);
        assert_eq!(s.summary(), "Fast DDS shared-memory transport (6)");
    }

    #[test]
    fn classifies_other_stacks_and_ignores_the_rest() {
        assert_eq!(
            classify("fast_datasharing_01.0f.aa"),
            Some(ShmKind::FastDdsDataSharing)
        );
        assert_eq!(classify("iceoryx_mgmt"), Some(ShmKind::Iceoryx));
        assert_eq!(classify("iox2_abc"), Some(ShmKind::Iceoryx));
        for n in ["", "pulse-shm-1", "robodr", "fastrtps", "x_el"] {
            assert_eq!(classify(n), None, "{n}");
        }
        assert!(scan_names(["a", "b"]).is_empty());
    }

    #[test]
    fn scan_is_bounded_and_a_missing_dir_is_empty() {
        let many = std::iter::repeat_n("fastrtps_port1", MAX_ENTRIES + 5);
        let s = scan_names(many);
        assert!(s.truncated);
        assert_eq!(s.found, vec![(ShmKind::FastDdsShm, MAX_ENTRIES as u64)]);
        let s = scan_dir(Path::new("/nonexistent/robodr-shm")).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn scan_dir_reads_names_only() {
        let d = std::env::temp_dir().join(format!("robodr-shm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("fastrtps_port7411"), b"").unwrap();
        std::fs::write(d.join("iceoryx_mgmt"), b"").unwrap();
        let s = scan_dir(&d).unwrap();
        assert_eq!(
            s.found,
            vec![(ShmKind::FastDdsShm, 1), (ShmKind::Iceoryx, 1)]
        );
        std::fs::remove_dir_all(&d).ok();
    }
}
