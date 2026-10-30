//! Known DDS vendor ids (the `vendorId` in the RTPS header / INFO_SRC and the
//! `PID_VENDORID` SPDP parameter).
//!
//! Vendor ids are assigned by the OMG ("DDS Vendor ID" list, linked from the
//! DDSI-RTPS spec §9.3.1.5). The table below was written from memory of that
//! list and of Wireshark's RTPS dissector, not fetched from the OMG site (this
//! environment is air-gapped). Entries with `verified: false` are the ones the
//! author is not certain of; treat their names as hints, never as a basis for
//! a trust decision. The ids that matter most for ROS 2 (eProsima Fast DDS
//! `0x010f`, Eclipse Cyclone DDS `0x0110`, RTI Connext `0x0101`, GurumDDS
//! `0x0111`) are ones the author is confident of and also match the constants
//! hard-coded in those stacks' sources.
//!
//! A vendor id is self-declared by the sender and unauthenticated: anyone can
//! put `0x010f` in a header. It is useful for diagnostics and for picking
//! vendor-specific parsing, not for identity.

/// One entry of the vendor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorInfo {
    /// Two-octet vendor id as a big-endian number (`[0x01, 0x0f]` -> `0x010f`).
    pub id: u16,
    /// Vendor / product name.
    pub name: &'static str,
    /// `false` when the author is not certain of the id -> name mapping.
    pub verified: bool,
}

const fn v(id: u16, name: &'static str, verified: bool) -> VendorInfo {
    VendorInfo { id, name, verified }
}

/// The known vendor ids, sorted by id.
pub const KNOWN_VENDORS: &[VendorInfo] = &[
    v(0x0101, "RTI Connext DDS", true),
    v(0x0102, "ADLINK OpenSplice DDS (PrismTech)", true),
    v(0x0103, "OCI OpenDDS", true),
    v(0x0104, "MilSoft Mil-DDS", true),
    v(0x0105, "Kongsberg InterCOM DDS", true),
    v(0x0106, "Twin Oaks CoreDX DDS", true),
    v(0x0107, "Lakota Technical Solutions", false),
    v(0x0108, "ICOUP Consulting", false),
    v(0x0109, "ETRI Diamond DDS", false),
    v(0x010a, "RTI Connext DDS Micro", true),
    v(0x010b, "ADLINK Vortex Cafe", false),
    v(0x010c, "PrismTech (ADLINK) DDS", false),
    v(0x010d, "ADLINK Vortex Lite", false),
    v(0x010e, "Technicolor Qeo", false),
    v(0x010f, "eProsima Fast DDS", true),
    v(0x0110, "Eclipse Cyclone DDS", true),
    v(0x0111, "GurumNetworks GurumDDS", true),
    v(0x0112, "Atostek RustDDS", true),
    v(0x0113, "Nanjing Zhenrong ZRDDS", false),
    v(0x0114, "S2E Software Systems Dust DDS", false),
];

/// `VENDORID_UNKNOWN` (`{0x00, 0x00}`).
pub const VENDOR_UNKNOWN: [u8; 2] = [0, 0];

/// Look up a vendor id. `None` for unknown ids (including `0x0000`).
pub fn vendor_info(id: [u8; 2]) -> Option<&'static VendorInfo> {
    let id = u16::from_be_bytes(id);
    KNOWN_VENDORS
        .binary_search_by_key(&id, |v| v.id)
        .ok()
        .and_then(|i| KNOWN_VENDORS.get(i))
}

/// The vendor's name, if the id is in the table.
pub fn vendor_name(id: [u8; 2]) -> Option<&'static str> {
    vendor_info(id).map(|v| v.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(KNOWN_VENDORS.windows(2).all(|w| w[0].id < w[1].id));
    }

    #[test]
    fn ros2_relevant_vendors() {
        assert_eq!(vendor_name([0x01, 0x0f]), Some("eProsima Fast DDS"));
        assert_eq!(vendor_name([0x01, 0x10]), Some("Eclipse Cyclone DDS"));
        assert_eq!(vendor_name([0x01, 0x01]), Some("RTI Connext DDS"));
        assert_eq!(
            vendor_name([0x01, 0x02]),
            Some("ADLINK OpenSplice DDS (PrismTech)")
        );
        assert_eq!(vendor_name([0x01, 0x03]), Some("OCI OpenDDS"));
        assert!(vendor_info([0x01, 0x0f]).unwrap().verified);
    }

    #[test]
    fn unknown_ids() {
        assert_eq!(vendor_name(VENDOR_UNKNOWN), None);
        assert_eq!(vendor_name([0xff, 0xff]), None);
        assert_eq!(vendor_name([0x01, 0x00]), None);
    }
}
