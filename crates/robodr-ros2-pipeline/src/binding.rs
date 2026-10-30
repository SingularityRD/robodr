//! Participant ↔ source-IP binding: who may speak for a GUID prefix.
//!
//! # The problem
//!
//! Without DDS-Security every GUID on the bus is a *claim*. An SEDP
//! announcement whose `PID_ENDPOINT_GUID` carries the prefix of a profiled
//! participant (say nav2) is attributed to that participant by the RTPS
//! parser, whatever host sent it, and the profile then accepts its
//! `rt/cmd_vel` writer. The sender can even put the victim's prefix in the
//! RTPS header, so "header prefix ≠ endpoint prefix" alone does not catch it.
//!
//! # What this module does
//!
//! It learns, per GUID prefix, the **source IPs** its SPDP announcements
//! arrive from and the **unicast locators** it advertises, and judges every
//! SEDP endpoint announcement against that binding:
//!
//! | Situation | Verdict |
//! |---|---|
//! | the prefix is pinned in the config (`participant_ips`) and the source IP is one of the pinned IPs | ok |
//! | pinned, other source IP | mismatch |
//! | bound by SPDP, source IP is a bound source IP or an advertised unicast locator IP | ok |
//! | bound by SPDP, other source IP | mismatch |
//! | loopback source (`127.0.0.0/8`, `::1`) received on a **non-loopback** interface ([`Ingress::External`]) | **spoofed**: mismatch, always **Critical** (SPDP: not learned) |
//! | loopback source on the loopback interface (or, unless `strict_loopback_ingress`, of unknown ingress) for a participant that is **same-host** (pinned / bound / advertised addresses include a loopback or local address of this host) | ok |
//! | relayed (sender prefix ≠ owner prefix, i.e. INFO_SRC / foreign header) or GUID conflict (`PID_PARTICIPANT_GUID` ≠ endpoint GUID prefix), from a configured discovery-server IP | ok (the relay is trusted) |
//! | relayed / GUID conflict from any other IP | mismatch |
//! | no binding yet (SEDP seen before SPDP) | **held** for `hold`; re-judged when the SPDP arrives; still unbound when the hold expires → "never announced" |
//!
//! A mismatch is [`rules::ENDPOINT_SOURCE_MISMATCH`]: **Critical** for a
//! writer on a motion topic of the profile (`motion_envelopes`), **High**
//! otherwise (readers on motion topics included: a reader cannot command,
//! matching the profile's own reader/writer split). "Never announced" is
//! [`rules::ENDPOINT_UNANNOUNCED_PARTICIPANT`], **Medium** (**High** for a
//! writer on a motion topic). An *ambiguous* announcement (the datagram
//! carried conflicting duplicate topic / type / GUID parameters, so another
//! DDS stack may act on a topic other than the one parsed) is judged worst
//! case: a writer in it counts as a motion writer whenever the profile has
//! motion topics.
//!
//! SPDP itself is judged too: an SPDP for an already-bound prefix from an IP
//! outside its binding, or a relayed SPDP from a non-discovery-server IP, is
//! [`rules::PARTICIPANT_SOURCE_MISMATCH`] (High for a profiled participant,
//! Medium otherwise) and is **not learned**.
//!
//! # Same-host traffic over loopback (trust model)
//!
//! DDS stacks talk to participants on the same host through the loopback
//! interface: Fast DDS rewrites a unicast locator that is one of this host's
//! own addresses to `127.0.0.1` (`transform_remote_locator`), so a
//! participant whose SPDP arrived from `192.168.50.10` sends its SEDP to a
//! local peer from `127.0.0.1`, over `lo` (which the default capture set
//! includes). Judged against the SPDP source alone, every such legitimate
//! writer would be a Critical mismatch.
//!
//! The rule: a datagram whose source is a loopback address is attributed to
//! **this host**. It is accepted for a participant that is itself on this
//! host, i.e. one of its pinned IPs, bound SPDP source IPs or advertised
//! locator IPs is a loopback address or a **local address** of this host
//! (`local_addresses`, plus addresses detected at start-up
//! ([`detect_local_addresses`], `binding.detect_local_addresses`), plus
//! non-loopback source addresses seen *on the loopback interface*, which
//! only this host can put there). A remote participant's prefix spoken
//! over loopback is still a mismatch.
//!
//! Why this does not open a bypass:
//!
//! - Only the host's own kernel can put a packet on `lo`; a process that can
//!   do that already runs on the robot (host compromise, covered by Pulsar's
//!   process monitoring, see Limits). On such a host every participant
//!   shares the host's IPs anyway.
//! - A loopback source **seen on a non-loopback interface**
//!   ([`Ingress::External`]) can only be forged; it is reported as a
//!   Critical mismatch for every endpoint and SPDP in it, whatever the
//!   topic. (Linux also drops such IPv4 packets as martians unless
//!   `route_localnet` is set; IPv6 `::1` handling was not verified, which is
//!   why the sensor does not rely on the kernel.)
//! - Passive capture reports the ingress **per packet**
//!   ([`crate::source::ingress_of_packet`]): live `AF_PACKET` from the
//!   kernel's `sockaddr_ll` (hardware type `ARPHRD_LOOPBACK` or not, also
//!   when bound to every interface), pcapng from each packet's Interface
//!   Description Block (`if_name`), and Linux cooked captures
//!   (`tcpdump -i any`, SLL/SLL2) from the frame header. Those datagrams
//!   are `Loopback` or `External`, never `Unknown`, so the forged case above
//!   is caught without `strict_loopback_ingress`.
//! - When the source cannot tell the interface ([`Ingress::Unknown`]: the
//!   SPDP socket, a classic pcap of Ethernet/raw-IP frames whose interface
//!   was not named, a pcapng interface without `if_name`) a loopback source
//!   is treated as same-host traffic by default — an attacker who forges
//!   `127.0.0.1` from the wire reaches the sensor but (IPv4) not the robot's
//!   DDS stack, so the miss is of an attack that cannot land.
//!   `strict_loopback_ingress = true` judges such datagrams against the
//!   binding instead (then same-host SEDP over `lo` received on the SPDP
//!   socket is a mismatch again: only use it when every source is
//!   ingress-aware). Interface names in capture *files* are the capturing
//!   host's and the loopback flag derived from them is a heuristic
//!   (`robodr_capture::ingress::loopback_by_name`); live capture and cooked
//!   headers do not depend on names.
//!
//! # Bootstrapping decision (SEDP before SPDP)
//!
//! DDS stacks send SEDP only after SPDP, so on a running bus SPDP precedes
//! SEDP. SEDP-before-SPDP happens when the sensor (re)starts mid-session:
//! the robot's next SPDP beacon can be up to one announcement period away
//! (Fast DDS ~3 s, Cyclone DDS up to 30 s). We therefore **hold judgement**
//! for `hold` (default 30 s, `binding.hold_ms`), bounded to `max_pending`
//! held announcements. When the SPDP arrives within the window the held
//! announcement is judged like a fresh one (so a spoofed one from the wrong
//! IP still becomes a Critical mismatch). When the window expires, or the
//! held queue overflows (oldest first), it becomes a Medium
//! "endpoint from never-announced participant" finding — an overflow can
//! therefore not be used to make held announcements disappear. A pinned
//! prefix (`participant_ips`) is judged immediately; it is never held.
//!
//! # Learning, refresh, expiry, eviction
//!
//! - First SPDP for a prefix (sent by the prefix itself, i.e. not relayed)
//!   binds its source IP and its unicast locator IPs (metatraffic + default).
//!   Unspecified and multicast addresses are ignored.
//! - Later SPDP from a bound IP or a locator IP refreshes the binding (adds
//!   the source IP, replaces the locators). This is how multi-homed hosts
//!   bind all their interfaces: each interface's IP is in the locators.
//! - A binding expires one lease after its last refresh (the SPDP
//!   `lease_duration`, clamped to 10 s..=600 s, default 100 s — the RTPS
//!   default). An expired prefix may be re-bound by the next SPDP from any IP
//!   (it mirrors DDS: a participant whose lease expired is gone). While the
//!   real participant is alive and beaconing, nobody else can take its
//!   prefix over.
//! - A self-dispose (SPDP `PID_STATUS_INFO`) from a bound IP removes the
//!   binding.
//! - The table is bounded (`max_participants`). When full, the least
//!   recently refreshed **unprofiled** prefix is evicted first, so a spray of
//!   fake participants cannot push the profiled ones out; only if every entry
//!   is profiled is the oldest profiled one evicted. Evictions are counted
//!   and O(log n) (an ordered index), so a prefix flood costs no O(n) scans.
//! - SPDP relayed by a configured discovery server teaches the locators only
//!   (the server's own IP is never bound to the relayed prefix).
//!
//! # Quarantine locators
//!
//! The executor quarantines a participant by dropping UDP to / from its
//! SPDP unicast locators (it proves them outside the motion control path)
//! plus RTPS sent by its GUID prefix. [`BindingTable::quarantine_target`]
//! gives agentd those locators. A SOC's order comes minutes after the
//! detection, when the rogue has usually left (dispose, lease expiry) or
//! been evicted by a prefix flood; the live binding alone then has nothing
//! (red team F3). So the table also remembers, per prefix, the unicast
//! locators of its last **trusted** SPDP (sent by the participant itself
//! from a bound or fresh address, or relayed by a configured discovery
//! server) and the **observed evidence**: the source addresses its own
//! SPDP and its accepted endpoint announcements arrived from. Kept for
//! [`LOCATOR_RETENTION`], bounded by [`MAX_LOCATOR_HISTORY`] prefixes and
//! [`MAX_LOCATOR_HISTORY_PER_SOURCE`] per first observed source address,
//! evicted by [`Rank`] then age: SPDP-only < active (announced an endpoint)
//! < raised a High finding < raised a Critical finding < named by a SOC
//! request < profiled (review M6: a spray, even of active prefixes from
//! one address, cannot push out a rogue that raised a Critical finding).
//! When the whole table is full, the **fullest per-source bucket** gives up
//! its lowest-ranked, oldest entry first (review R2-4: a spray of
//! Critical-ranked prefixes from 10 addresses evicts its own entries, not
//! a lone departed rogue's); a SOC-named entry is never evicted for a
//! lower-ranked one and a profiled one never.
//!
//! What is handed out (review of the F3 fix, H1, H2, M5, M7):
//!
//! - **Only addresses the participant was seen sending from.** An
//!   announced locator whose address is not among the prefix's observed
//!   source addresses is left out: SPDP is unauthenticated, so a rogue can
//!   announce anyone's address, but to get it handed out it must also send
//!   from it (source spoofing). This keeps an absent legitimate host's
//!   address (M5), a poison locator outside the quarantine scope or on the
//!   motion path, and loopback (always left out) out of the set (H2b).
//! - **Never the robot's own.** A locator a profiled participant announces
//!   (live, or remembered: even while its lease has run out) or an address
//!   pinned to another prefix is left out. A profiled prefix's remembered
//!   locators are **never written by a foreign host**: an SPDP for a
//!   profiled prefix with no live binding from an address its evidence
//!   never saw (nor a locator address, nor same-host loopback) makes the
//!   prefix **contested** with a Critical `participant_source_mismatch`
//!   (H1; before, it silently re-bound and overwrote them).
//! - **Never the robot's computer** (review R2-5): for a prefix that is
//!   not itself profiled, no port on this host's own address or on an
//!   address pinned to a profiled participant is handed out: a decoy
//!   spoofing the robot computer's address cannot get the ports of the
//!   robot's other, unprofiled participants there. Review R3-6: an
//!   address a profiled participant was only **learned** at (first-come
//!   SPDP) may be an attacker's that announced the profiled prefix before
//!   the real participant (or after its evidence lapsed), so it no longer
//!   shields other ports; it is never cut whole (below). Pin the profiled
//!   prefixes (or rely on this host's addresses) to keep R2-5 for every
//!   host.
//! - **Source addresses** (review R3-1): [`QuarantineTarget::addresses`]
//!   are the prefix's observed source addresses the executor may cut
//!   **whole** (all UDP to and from the robot's DDS ports, any source
//!   port: Fast DDS sends from ephemeral ports, which a locator rule never
//!   matches). Left out, with the reason: loopback, this host's addresses,
//!   an address pinned to another prefix, a profiled participant's pinned
//!   address, a profile identity's `ips`, and any address a profiled
//!   participant (other than the target) was learned at. A whole-address
//!   drop cuts every participant on that host (shared-host caveat, control
//!   plane contract §6a). [`QuarantineTarget::evidence_truncated`] says an
//!   observed address or announced locator was forgotten (per-prefix
//!   caps): such a quarantine is never `full`.
//! - **Claims do not take a locator away; evidence decides.** A decoy
//!   copying the rogue's locators from another address was never seen at
//!   them and changes nothing (H2a). Two prefixes seen at the **same**
//!   address announcing one ip:port share that host (review R2-3): both
//!   get it, whether the second one is the rogue's own self-decoy (no
//!   spoofing needed; before, each contested the other and the rogue was
//!   quarantined by GUID prefix only), its next prefix after a restart,
//!   or a decoy spoofing its address.
//! - **A named rogue keeps its history.** A prefix ranked High or above
//!   (in a locked profile every unknown participant raises a High finding)
//!   that is re-announced from a new address after its lease ran out keeps
//!   its remembered evidence, locators and rank: the new ones are merged in
//!   (bounded: [`MAX_BOUND_IPS`] sources, [`MAX_LOCATOR_IPS`] locators,
//!   newest first). Before (review R2-3), the fresh re-bind replaced them,
//!   so a rogue the SOC had named could reduce its quarantine to its second
//!   address.
//! - **GUID-prefix-only.** [`QuarantineTarget::guid_only`] tells the
//!   executor that the prefix was seen and is not one of the robot's own
//!   (profiled, pinned, contested): with no locator left it may quarantine
//!   by the GUID-prefix payload drop alone, which matches RTPS sent by that
//!   prefix only and is rendered after every motion-path accept.
//! - A **contested** or **pinned** prefix gets nothing, and no GUID-only.
//! - Every left-out locator is listed with its reason ([`excluded`]).
//! - Another input's locators (agentd's `ros2_participant_discovered`
//!   events) are used only for a prefix the table does not know, through
//!   the same filters with the event's source as evidence
//!   ([`BindingTable::vouch_external`], M7).
//! - The executor still re-checks every locator against its motion control
//!   path and quarantine scope and the humanoid / approval rules.
//!
//! # Limits (be honest)
//!
//! - **UDP source addresses are not authenticated.** An attacker on the same
//!   L2 segment can forge the victim's source IP; this check then passes.
//!   It raises the bar (an attacker must forge the IP *and* the prefix, and
//!   cannot receive replies), it does not replace DDS-Security.
//! - **Quarantine locators** (module docs above) rest on observed source
//!   addresses, which can be forged too: a rogue that spoofs the address of
//!   an unprofiled participant (present or absent), and announces its exact
//!   ip:port, gets that ip:port handed out (since review R2-3 a live owner
//!   no longer contests it: a same-address claim is the same host) and,
//!   since review R3-1, that address cut whole when it is inside the
//!   executor's quarantine scope (accepted limit R3-3). This host's
//!   address and an address pinned to a profiled participant are never
//!   handed out to another prefix; a profile identity's or a learned
//!   profiled host's address is never cut whole. The evidence is per address, not per
//!   port (RTPS datagrams reach the table without their source port). A
//!   participant known only through a discovery server has no evidence:
//!   GUID-prefix-only. So is a rogue that announces its locators only on
//!   addresses it never sends from: the SOC's answer then says
//!   `containment: "guid_only"` (control-plane contract §6a). The memory
//!   is not persisted: after an agentd restart a departed rogue is
//!   quarantined by GUID prefix only (the executor refuses if agentd does
//!   not know the prefix at all).
//! - A merged history (above) also keeps a moved unknown participant's old
//!   address for [`LOCATOR_RETENTION`]: a quarantine of that prefix may cut
//!   a host that took the address over in the meantime (within the
//!   executor's quarantine scope, never a profiled host or the motion
//!   path).
//! - A spray from more source addresses than [`MAX_LOCATOR_HISTORY`] /
//!   [`MAX_LOCATOR_HISTORY_PER_SOURCE`] buckets (spoofed sources) can still
//!   evict a departed rogue's memory unless the SOC named it first.
//! - A profiled participant that comes back (lease run out, or after a
//!   dispose) from an address its remembered evidence never saw (a new
//!   DHCP lease) makes its prefix **contested** for the life of the table
//!   (below; only pinning resolves it). The trigger itself lapses with the
//!   remembered evidence ([`LOCATOR_RETENTION`], 24 h): after that, an SPDP
//!   for the prefix from a new address binds first-come again (loud only
//!   when the real participant returns and contests it).
//! - **First-come profiled addresses** (review R3-6). An attacker that
//!   announces a profiled prefix first (before the real participant, or
//!   after its evidence lapsed) is learned at its address. That address is
//!   then never cut **whole** for another prefix (it might be the robot's
//!   computer: RoboDR cannot tell until the real participant contests the
//!   prefix, and not even then which host is which), so a rogue there is
//!   quarantined by its own locators and the GUID-prefix drop only
//!   (`containment: "partial"`, reason "learned, not commissioned"). Only
//!   pins (`participant_ips`) and this host's addresses are trusted as the
//!   robot's own; pin the profiled prefixes to close this.
//! - Every participant on one host shares that host's IPs, so a process on
//!   the robot's own computer can speak for any participant there. That is
//!   host compromise, which Pulsar's process monitoring covers, not this.
//! - **DHCP / multi-homed / NAT / containers**: an IP change of a live
//!   participant (new DHCP lease before the binding expires, a container
//!   behind NAT, a VPN) shows up as a mismatch. Robots with such networks
//!   must be commissioned: either static addressing, or `participant_ips`
//!   pins listing every address the participant can use, or a
//!   `discovery_server` list. This is a **commissioning item**.
//! - **Contested prefixes.** RoboDR cannot tell which of two hosts is the
//!   real owner of a GUID prefix: the first SPDP is not more trustworthy than
//!   the second (an attacker who announces a profiled prefix before the real
//!   participant ever did would otherwise keep it). So when a live
//!   (unexpired) binding of a **profiled** prefix is claimed by an SPDP from
//!   an IP outside it, the prefix becomes **contested**: a Critical
//!   [`rules::PARTICIPANT_SOURCE_MISMATCH`] is raised and from then on
//!   [`BindingTable::allows_from`] answers `Some(false)` for **every** IP
//!   (the first host's included), so endpoints, motion samples and
//!   safety-state samples attributed to the prefix are untrusted (endpoint
//!   mismatches are Critical). It stays contested for the life of the table
//!   (expiry, dispose and eviction do not clear it); the operator resolves it
//!   by pinning the prefix (`participant_ips`), which takes precedence. An
//!   attacker who can send one SPDP can therefore make a profiled participant
//!   untrusted (fail closed, loudly) but can never make a forged one
//!   trusted. Unprofiled prefixes keep the first-come binding (their
//!   conflicting SPDP is reported, High / Medium, and not learned).
//!   Pin the profiled prefixes to close all of this up front.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use robodr_events::graph::{ActionRole, RosNameKind};
use robodr_events::profile::Profile;
use robodr_events::{Deviation, Severity};
use robodr_rtps::{
    hex12, EndpointInfo, EndpointKind, GuidPrefix, Locator, ParticipantRemoval, SpdpInfo,
    LOCATOR_KIND_UDPV4, LOCATOR_KIND_UDPV6,
};

use crate::sanitize::{clip_name, MAX_TEXT_CHARS};

/// Rule ids raised by the binding check.
pub mod rules {
    /// An SEDP endpoint announcement for a participant arrived from an IP
    /// not bound to it, or relayed / GUID-conflicting from an untrusted IP.
    pub const ENDPOINT_SOURCE_MISMATCH: &str = "robot.ros2.endpoint_source_mismatch";
    /// An SEDP endpoint for a participant that never announced itself (no
    /// SPDP within the hold window, or the held queue overflowed).
    pub const ENDPOINT_UNANNOUNCED_PARTICIPANT: &str =
        "robot.ros2.endpoint_unannounced_participant";
    /// An SPDP announcement for a bound participant from an IP outside its
    /// binding, or relayed by an untrusted IP. Not learned.
    pub const PARTICIPANT_SOURCE_MISMATCH: &str = "robot.ros2.participant_source_mismatch";
}

/// Default hold window for SEDP seen before its participant's SPDP.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(30);
/// Largest configurable hold window.
pub const MAX_HOLD: Duration = Duration::from_secs(600);
/// Default binding table size.
pub const DEFAULT_MAX_PARTICIPANTS: usize = 1024;
/// Largest configurable binding table size.
pub const MAX_MAX_PARTICIPANTS: usize = 65_536;
/// Default (and max) number of held SEDP announcements.
pub const DEFAULT_MAX_PENDING: usize = 1024;
/// Source IPs remembered per participant (oldest dropped).
pub const MAX_BOUND_IPS: usize = 8;
/// Locator IPs remembered per participant.
pub const MAX_LOCATOR_IPS: usize = 32;
/// Pinned IPs per participant.
pub const MAX_PINNED_IPS: usize = 16;
/// Pinned participants.
pub const MAX_PINNED_PARTICIPANTS: usize = 4096;
/// Discovery-server IPs.
pub const MAX_DISCOVERY_SERVERS: usize = 32;
/// Local addresses of this host (configured + detected + learned).
pub const MAX_LOCAL_ADDRESSES: usize = 64;
/// Lease used when SPDP carries none (RTPS default `leaseDuration`).
pub const DEFAULT_LEASE: Duration = Duration::from_secs(100);
/// Participants whose last trusted SPDP unicast locators are remembered
/// after their binding is gone ([`BindingTable::quarantine_locators`]).
pub const MAX_LOCATOR_HISTORY: usize = 1024;
/// How long those locators are kept after the participant's last trusted
/// SPDP announcement.
pub const LOCATOR_RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Remembered prefixes per observed source address (the first address a
/// prefix was seen sending from): a spray from one address can push out
/// only its own (review M6).
pub const MAX_LOCATOR_HISTORY_PER_SOURCE: usize = 128;
/// Lease clamp.
pub const MIN_LEASE: Duration = Duration::from_secs(10);
pub const MAX_LEASE: Duration = Duration::from_secs(600);

/// Knobs of the binding check. Part of
/// [`PipelineOptions`](crate::PipelineOptions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingOptions {
    /// Run the binding check at all.
    pub enabled: bool,
    /// IPs of trusted discovery servers / relays: relayed and GUID-conflicting
    /// announcements from them are accepted.
    pub discovery_servers: Vec<IpAddr>,
    /// Pinned participant → allowed source IPs (authoritative, never
    /// learned over, never evicted).
    pub participant_ips: BTreeMap<GuidPrefix, Vec<IpAddr>>,
    /// How long an SEDP announcement from a not-yet-announced participant is
    /// held before it is reported as "never announced". Zero = report at once.
    pub hold: Duration,
    /// Max learned participants (clamped to 1..=[`MAX_MAX_PARTICIPANTS`]).
    pub max_participants: usize,
    /// Max held SEDP announcements (clamped to 1..=[`DEFAULT_MAX_PENDING`]).
    pub max_pending: usize,
    /// Addresses of **this** host (the robot computer the sensor runs on). A
    /// participant bound to / advertising / pinned to one of them is
    /// same-host, so its traffic over loopback is attributable to it (see
    /// the module docs). At most [`MAX_LOCAL_ADDRESSES`] are kept.
    pub local_addresses: Vec<IpAddr>,
    /// Add the host's addresses found by [`detect_local_addresses`] when the
    /// table is built. Off in `Default` (the library stays pure for tests and
    /// replays of another host's capture); on in the sensor config default.
    pub detect_local_addresses: bool,
    /// Judge loopback-sourced datagrams of unknown ingress
    /// ([`Ingress::Unknown`]) against the binding like any other source,
    /// instead of as same-host traffic. Only for ingress-aware deployments.
    pub strict_loopback_ingress: bool,
}

impl Default for BindingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            discovery_servers: Vec::new(),
            participant_ips: BTreeMap::new(),
            hold: DEFAULT_HOLD,
            max_participants: DEFAULT_MAX_PARTICIPANTS,
            max_pending: DEFAULT_MAX_PENDING,
            local_addresses: Vec::new(),
            detect_local_addresses: false,
            strict_loopback_ingress: false,
        }
    }
}

/// Which kind of interface a datagram was received on, as far as its source
/// knows. Decides how a loopback source address is judged (see the module
/// docs, "Same-host traffic over loopback").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Ingress {
    /// Not known (SPDP socket, capture files that do not record the
    /// interface; see the module docs).
    #[default]
    Unknown,
    /// A loopback interface (`lo`): only this host can send there.
    Loopback,
    /// A non-loopback interface: a loopback source address is forged.
    External,
}

/// Counters of the binding table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct BindingStats {
    /// New bindings from SPDP.
    pub learned: u64,
    /// SPDP from a bound IP / locator.
    pub refreshed: u64,
    /// Expired bindings taken over by a new SPDP.
    pub rebound: u64,
    /// Entries evicted to stay within `max_participants`.
    pub evicted: u64,
    /// Bindings removed by a self-dispose.
    pub removed: u64,
    /// SPDP rejected (mismatching or untrusted relay).
    pub spdp_mismatches: u64,
    /// Endpoint announcements judged a mismatch.
    pub endpoint_mismatches: u64,
    /// Endpoint announcements held for a missing SPDP.
    pub held: u64,
    /// Held announcements resolved by a later SPDP.
    pub held_resolved: u64,
    /// Held announcements reported as never announced (expiry or flush).
    pub held_expired: u64,
    /// Held announcements pushed out by a full queue (also reported).
    pub held_overflow: u64,
    /// Datagrams whose source IP did not parse (binding not judged).
    pub unparsed_src_ip: u64,
    /// Announcements accepted as same-host traffic over loopback.
    pub same_host_loopback: u64,
    /// Announcements with a loopback source received on a non-loopback
    /// interface (forged; reported).
    pub spoofed_loopback: u64,
    /// Local addresses learned from traffic on the loopback interface.
    pub local_learned: u64,
    /// Profiled prefixes that became contested (claimed by a second host).
    pub contested: u64,
    /// Remembered quarantine locators forgotten to stay within
    /// [`MAX_LOCATOR_HISTORY`] / [`MAX_LOCATOR_HISTORY_PER_SOURCE`].
    pub locators_forgotten: u64,
    /// Profiled prefixes announced, after their lease ran out, from a host
    /// their remembered evidence never saw (made contested; review H1).
    pub foreign_rebinds: u64,
    /// Prefixes ranked High or above re-announced from a new address after
    /// their lease ran out: evidence merged, not replaced (review R2-3).
    pub evidence_merged: u64,
    /// Prefixes not remembered because every entry left was SOC-named or
    /// profiled (review R2-4).
    pub locators_not_remembered: u64,
}

/// Is `ip` a loopback address (`127.0.0.0/8`, `::1`, or an IPv4-mapped
/// `::ffff:127.x.y.z`)?
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    canonical_ip(ip).is_loopback()
}

/// Parse `/proc/net/fib_trie` (the `/32 host LOCAL` entries are this host's
/// IPv4 addresses) and `/proc/net/if_inet6` (one IPv6 address per line, 32
/// hex digits first). Pure, for tests; see [`detect_local_addresses`].
/// Loopback, unspecified and multicast addresses are skipped; at most
/// [`MAX_LOCAL_ADDRESSES`] are returned; malformed lines are ignored.
pub fn parse_local_addresses(fib_trie: &str, if_inet6: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    let push = |ip: IpAddr, out: &mut Vec<IpAddr>| {
        let ip = canonical_ip(ip);
        if !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !out.contains(&ip)
            && out.len() < MAX_LOCAL_ADDRESSES
        {
            out.push(ip);
        }
    };
    let mut last: Option<std::net::Ipv4Addr> = None;
    for line in fib_trie.lines() {
        let t = line.trim_start_matches([' ', '|', '+', '-']).trim();
        if let Ok(a) = t.parse::<std::net::Ipv4Addr>() {
            last = Some(a);
        } else if t.starts_with("/32 host LOCAL") {
            if let Some(a) = last {
                push(IpAddr::V4(a), &mut out);
            }
        }
    }
    for line in if_inet6.lines() {
        let Some(hex) = line.split_whitespace().next() else {
            continue;
        };
        if hex.len() != 32 || !hex.is_ascii() {
            continue;
        }
        let mut b = [0u8; 16];
        let ok = b.iter_mut().enumerate().all(|(i, o)| {
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map(|v| *o = v)
                .is_ok()
        });
        if ok {
            push(IpAddr::from(b), &mut out);
        }
    }
    out
}

/// This host's non-loopback addresses, from `/proc` (Linux). Empty when
/// `/proc` is unreadable (other OSes, sandboxes): configure
/// `local_addresses` then. Reads two small files; call once at start-up.
pub fn detect_local_addresses() -> Vec<IpAddr> {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    parse_local_addresses(&read("/proc/net/fib_trie"), &read("/proc/net/if_inet6"))
}

/// IPv4-mapped IPv6 → IPv4, so `::ffff:10.0.0.5` and `10.0.0.5` match.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Parse a datagram source IP (as the sources report it).
pub fn parse_src_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse::<IpAddr>().ok().map(canonical_ip)
}

/// The IP of a UDPv4/UDPv6 locator, if it is a usable unicast address.
pub fn locator_ip(l: &Locator) -> Option<IpAddr> {
    let ip = match l.kind {
        LOCATOR_KIND_UDPV4 => {
            let a = &l.address;
            IpAddr::from([a[12], a[13], a[14], a[15]])
        }
        LOCATOR_KIND_UDPV6 => IpAddr::from(l.address),
        _ => return None,
    };
    let ip = canonical_ip(ip);
    (!ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::from([255, 255, 255, 255]))
        .then_some(ip)
}

/// Parse a 24-hex-digit GUID prefix (case-insensitive).
pub fn parse_prefix(s: &str) -> Option<GuidPrefix> {
    let s = s.trim();
    if s.len() != 24 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 12];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Is `topic` (an RTPS topic name) a motion topic of the profile?
pub fn is_motion_topic(profile: &Profile, topic: &str) -> bool {
    let ep = robodr_events::graph::Endpoint {
        guid_prefix: String::new(),
        topic: topic.to_string(),
        type_name: String::new(),
    };
    let rn = ep.ros_name();
    matches!(
        rn.kind,
        RosNameKind::Topic
            | RosNameKind::ActionPart {
                role: ActionRole::Topic,
                ..
            }
    ) && profile.motion_envelopes.contains_key(&rn.name)
}

/// A finding produced by the binding check: the deviation and the source IP
/// it is attributed to.
/// The third element is the GUID prefix the finding is about (structured,
/// never parsed from text: agentd's discovery-flood aggregate names it).
pub type BindingFinding = (Deviation, String, Option<GuidPrefix>);

#[derive(Debug, Clone)]
struct Entry {
    bound_ips: VecDeque<IpAddr>,
    locator_ips: Vec<IpAddr>,
    /// The SPDP unicast locators (metatraffic and default) with their ports,
    /// as last announced through a trusted path ([`BindingTable::spdp_unicast`]).
    unicast: Vec<SocketAddr>,
    last_refresh: Instant,
    lease: Duration,
    /// A bound source address was forgotten ([`MAX_BOUND_IPS`]).
    forgot: bool,
}

impl Entry {
    fn allows(&self, ip: IpAddr) -> bool {
        self.bound_ips.contains(&ip) || self.locator_ips.contains(&ip)
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_refresh) > self.lease
    }

    fn add_bound(&mut self, ip: IpAddr) {
        if !self.bound_ips.contains(&ip) {
            if self.bound_ips.len() >= MAX_BOUND_IPS {
                self.bound_ips.pop_front();
                self.forgot = true;
            }
            self.bound_ips.push_back(ip);
        }
    }
}

/// The SPDP unicast locators a participant last announced through a
/// trusted path, kept after its binding is gone (lease expiry, dispose,
/// eviction) for a later quarantine ([`BindingTable::quarantine_locators`]).
#[derive(Debug, Clone)]
struct LastLocators {
    unicast: Vec<SocketAddr>,
    /// Observed evidence: the source addresses this prefix's own SPDP (not
    /// relayed) and its accepted endpoint announcements arrived from
    /// (bounded by [`MAX_BOUND_IPS`]). Only locators on one of these are
    /// handed out for a quarantine.
    sources: VecDeque<IpAddr>,
    /// Its last trusted SPDP.
    at: Instant,
    /// How long it is kept under pressure (module docs).
    rank: Rank,
    /// Per-source eviction bucket: the first address it was seen sending
    /// from (`None`: learned through a discovery server only).
    bucket: Option<IpAddr>,
    /// An observed source address or an announced locator was forgotten
    /// ([`MAX_BOUND_IPS`], [`MAX_LOCATOR_IPS`]): a quarantine of the prefix
    /// can never be `full` (review R3-1).
    forgot: bool,
}

impl LastLocators {
    fn add_source(&mut self, ip: IpAddr) {
        if !self.sources.contains(&ip) {
            if self.sources.len() >= MAX_BOUND_IPS {
                self.sources.pop_front();
                self.forgot = true;
            }
            self.sources.push_back(ip);
        }
    }

    /// Was `ip` seen for this prefix: an observed source or an announced
    /// locator address?
    fn knows(&self, ip: IpAddr) -> bool {
        self.sources.contains(&ip) || self.unicast.iter().any(|l| canonical_ip(l.ip()) == ip)
    }
}

/// Eviction rank of remembered quarantine locators: the lowest go first
/// (oldest first within a rank). Module docs, "Quarantine locators".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// Only SPDP was seen.
    SpdpOnly,
    /// It announced an endpoint from a bound source.
    Active,
    /// It raised a High finding.
    High,
    /// It raised a Critical finding.
    Critical,
    /// A SOC request named it (`quarantine_node`).
    SocReferenced,
    /// A profiled participant (the robot's own): never evicted by others.
    Profiled,
}

/// Why a remembered locator is not handed out for a quarantine
/// ([`QuarantineTarget::excluded`]). Stable strings (they reach the
/// executor's answer).
pub mod excluded {
    pub const LOOPBACK: &str = "loopback address";
    pub const NOT_OBSERVED: &str =
        "the participant was never seen sending from this address (announced only)";
    pub const PINNED_ELSEWHERE: &str = "address pinned to another participant (participant_ips)";
    pub const PROFILED: &str = "announced by a profiled participant (the robot's own)";
    /// Review R2-5: any port on an address a profiled participant was seen
    /// on, or announced (the robot computer's own address). Since review
    /// R3-6 only an address pinned to a profiled participant
    /// (`participant_ips`); this host's own is [`THIS_HOST`].
    pub const PROFILED_HOST: &str =
        "address of a profiled participant's host (the robot's own computer)";
    /// Review R3-1 / R3-6: an address a profiled participant was learned
    /// at (first-come SPDP, not commissioned) is never cut whole: it may be
    /// the robot's computer, or an attacker's that announced a profiled
    /// prefix first. Its exact locators may still be cut.
    pub const LEARNED_PROFILED_HOST: &str =
        "address a profiled participant was learned at (not commissioned): never cut whole; \
         pin it (participant_ips) or commission the identity's ips";
    /// Review R3-1: this host's own address: never cut whole, and none of
    /// its ports for a non-profiled prefix (review R2-5).
    pub const THIS_HOST: &str = "this host's own address (the computer RoboDR runs on)";
    /// Review R3-1: an address a profile identity lists (commissioned for
    /// the robot's participants) is never cut whole. A non-profiled
    /// prefix's own locators there may be cut (a rogue matching the
    /// identity from that address, red team F3).
    pub const IDENTITY_HOST: &str =
        "address listed in a profile identity's ips (the robot's own): never cut whole";
    /// No longer produced (review R2-3): two prefixes seen at the same
    /// address announcing one ip:port share a host and both get it. Kept
    /// for consumers matching the string.
    pub const CONTESTED_LIVE: &str =
        "contested: another live participant was seen at this address announcing it";
    /// No longer produced (review R2-3), see [`CONTESTED_LIVE`].
    pub const CONTESTED_LATER: &str =
        "contested: another participant announced it later from this address";
    pub const OTHER_FAMILY: &str = "address family differs from the other locators";
}

/// What agentd may hand the executor for a quarantine of one GUID prefix
/// ([`BindingTable::quarantine_target`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineTarget {
    /// Locators the executor may cut (it re-checks every one).
    pub locators: Vec<SocketAddr>,
    /// Announced locators left out, and why ([`excluded`]).
    pub excluded: Vec<(SocketAddr, &'static str)>,
    /// The table knows this prefix (live, remembered, profiled, pinned or
    /// contested). When `false` another source (agentd's event input) may
    /// be asked, filtered by [`BindingTable::vouch_external`].
    pub known: bool,
    /// The prefix may be quarantined by its GUID-prefix payload drop alone
    /// when no locator is left: it was seen, and it is not one of the
    /// robot's own (profiled, pinned or contested). The drop matches RTPS
    /// sent by that prefix only, so it cannot cut another participant.
    pub guid_only: bool,
    /// Review R3-1: the source addresses the prefix was seen sending from
    /// that the executor may cut whole (all UDP to and from the robot's
    /// DDS ports, any source port): not loopback, not this host's, not
    /// pinned to another prefix, not a profiled participant's host
    /// (commissioned or learned). One address family, the locators'.
    pub addresses: Vec<IpAddr>,
    /// Observed source addresses left out, and why ([`excluded`]).
    pub excluded_addresses: Vec<(IpAddr, &'static str)>,
    /// Some observed source address or announced locator of the prefix was
    /// forgotten (per-prefix caps): its quarantine is never `full`.
    pub evidence_truncated: bool,
}

/// An SEDP announcement waiting for its participant's SPDP. Only what is
/// needed to judge and report it is kept (the topic is truncated), so the
/// queue's memory is bounded by `max_pending * ~MAX_TEXT_CHARS`.
#[derive(Debug, Clone)]
struct Held {
    participant: GuidPrefix,
    kind: EndpointKind,
    topic: String,
    src_ip: IpAddr,
    ingress: Ingress,
    deadline: Instant,
    /// The datagram carried conflicting duplicate identity parameters.
    ambiguous: bool,
}

/// Why an endpoint announcement does not match its participant's binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mismatch {
    NotBound,
    NotPinned,
    Relayed,
    GuidConflict,
    SpoofedLoopback,
    Contested,
}

impl Mismatch {
    fn text(self) -> &'static str {
        match self {
            Self::NotBound => "which is not bound to it (not its SPDP source nor an advertised locator)",
            Self::NotPinned => "which is not one of its pinned participant_ips",
            Self::Relayed => {
                "relayed for it by another participant (INFO_SRC / foreign RTPS header) from an IP that is not a configured discovery server"
            }
            Self::GuidConflict => {
                "with PID_PARTICIPANT_GUID disagreeing with the endpoint GUID, from an IP that is not a configured discovery server"
            }
            Self::SpoofedLoopback => {
                "a loopback source address received on a non-loopback interface (forged source)"
            }
            Self::Contested => {
                "but its GUID prefix is contested (announced by SPDP from more than one host): \
                 no source is trusted for it until it is pinned in participant_ips"
            }
        }
    }
}

enum Verdict {
    Ok,
    Mismatch(Mismatch),
    Unbound,
}

/// The binding table plus the held-announcement queue. Pure: time is passed
/// in. See the module docs.
#[derive(Debug)]
pub struct BindingTable {
    opts: BindingOptions,
    entries: HashMap<GuidPrefix, Entry>,
    /// Eviction order: `(profiled, last_refresh, prefix)`, so the first
    /// element is the least recently refreshed unprofiled entry (O(log n)
    /// eviction even under a flood of fresh prefixes).
    order: BTreeSet<(bool, Instant, GuidPrefix)>,
    profiled: BTreeSet<GuidPrefix>,
    held: VecDeque<Held>,
    /// Held announcements per participant, so the per-SPDP / per-SEDP
    /// "anything held for it?" checks are O(1) instead of a queue scan.
    held_count: HashMap<GuidPrefix, usize>,
    /// Profiled, unpinned prefixes claimed by SPDP from two hosts (module
    /// docs, "Contested prefixes"). Bounded by the profile's participants.
    contested: BTreeSet<GuidPrefix>,
    /// This host's addresses (configured, detected, learned on loopback).
    local: Vec<IpAddr>,
    /// The profile's commissioned participant addresses (every identity's
    /// `ips`; review R3-6).
    identity_ips: BTreeSet<IpAddr>,
    /// Last trusted unicast locators per prefix, bounded by
    /// [`MAX_LOCATOR_HISTORY`] (module docs, "Quarantine locators").
    history: HashMap<GuidPrefix, LastLocators>,
    /// Eviction order of `history` per source bucket: `(rank, at,
    /// prefix)`, lowest rank first, oldest first
    /// ([`MAX_LOCATOR_HISTORY_PER_SOURCE`]; under global pressure the
    /// fullest bucket goes first: O(buckets) ≤ [`MAX_LOCATOR_HISTORY`]).
    history_by_source: HashMap<Option<IpAddr>, BTreeSet<(Rank, Instant, GuidPrefix)>>,
    stats: BindingStats,
}

fn kind_str(k: EndpointKind) -> &'static str {
    match k {
        EndpointKind::Writer => "writer",
        EndpointKind::Reader => "reader",
    }
}

/// A writer that could command motion: on a motion topic of the profile,
/// or in an ambiguous announcement (conflicting duplicate topic / GUID
/// parameters: another DDS stack may read a different topic than the one we
/// parsed) while the profile has motion topics at all. Worst case is assumed.
fn motion_capable_writer(
    profile: &Profile,
    kind: EndpointKind,
    topic: &str,
    ambiguous: bool,
) -> bool {
    kind == EndpointKind::Writer
        && (is_motion_topic(profile, topic) || (ambiguous && !profile.motion_envelopes.is_empty()))
}

fn truncate(s: &str) -> String {
    s.chars().take(MAX_TEXT_CHARS).collect()
}

impl BindingTable {
    /// `profiled`: the profile's participant prefixes (protected from
    /// eviction, and their SPDP mismatches are High).
    pub fn new(opts: BindingOptions, profile: &Profile) -> Self {
        let mut opts = opts;
        opts.max_participants = opts.max_participants.clamp(1, MAX_MAX_PARTICIPANTS);
        opts.max_pending = opts.max_pending.clamp(1, DEFAULT_MAX_PENDING);
        opts.hold = opts.hold.min(MAX_HOLD);
        for ips in opts.participant_ips.values_mut() {
            for ip in ips.iter_mut() {
                *ip = canonical_ip(*ip);
            }
        }
        for ip in opts.discovery_servers.iter_mut() {
            *ip = canonical_ip(*ip);
        }
        let mut local: Vec<IpAddr> = Vec::new();
        let detected = if opts.detect_local_addresses {
            detect_local_addresses()
        } else {
            Vec::new()
        };
        for ip in opts.local_addresses.iter().chain(&detected) {
            let ip = canonical_ip(*ip);
            if !ip.is_unspecified()
                && !ip.is_multicast()
                && !local.contains(&ip)
                && local.len() < MAX_LOCAL_ADDRESSES
            {
                local.push(ip);
            }
        }
        let identity_ips = profile
            .participant_identities
            .values()
            .flat_map(|id| id.ips.iter())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(canonical_ip)
            .collect();
        Self {
            local,
            identity_ips,
            profiled: profile
                .participants
                .iter()
                .filter_map(|p| parse_prefix(p))
                .collect(),
            opts,
            entries: HashMap::new(),
            order: BTreeSet::new(),
            held: VecDeque::new(),
            held_count: HashMap::new(),
            contested: BTreeSet::new(),
            history: HashMap::new(),
            history_by_source: HashMap::new(),
            stats: BindingStats::default(),
        }
    }

    pub fn options(&self) -> &BindingOptions {
        &self.opts
    }

    pub fn stats(&self) -> &BindingStats {
        &self.stats
    }

    /// Learned (not pinned) participants.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Held SEDP announcements.
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Is `prefix` a profiled participant (statically, or resolved at run
    /// time via [`BindingTable::set_profiled`])?
    pub fn is_profiled(&self, prefix: &GuidPrefix) -> bool {
        self.profiled.contains(prefix)
    }

    /// Is `prefix` currently bound (learned or pinned)?
    pub fn is_bound(&self, prefix: &GuidPrefix) -> bool {
        self.entries.contains_key(prefix) || self.opts.participant_ips.contains_key(prefix)
    }

    /// Mark `prefix` as profiled (or not) after the table was built: a
    /// prefix resolved to a profile identity at run time
    /// ([`crate::identity`]) gets the same eviction protection and
    /// severities as a statically profiled one.
    pub fn set_profiled(&mut self, prefix: GuidPrefix, profiled: bool) {
        if self.profiled.contains(&prefix) == profiled {
            return;
        }
        let at = self.entries.get(&prefix).map(|e| e.last_refresh);
        if let Some(at) = at {
            self.order.remove(&(!profiled, at, prefix));
            self.order.insert((profiled, at, prefix));
        }
        if profiled {
            self.profiled.insert(prefix);
            self.raise_rank(&prefix, Rank::Profiled);
        } else {
            self.profiled.remove(&prefix);
            if let Some(mut h) = self.history.remove(&prefix) {
                self.unindex_history(prefix, &h);
                h.rank = Rank::Active;
                self.index_history(prefix, &h);
                self.history.insert(prefix, h);
            }
        }
    }

    /// The SPDP unicast locators (ip:port, metatraffic and default) that
    /// participant `prefix` currently announces through a path this table
    /// trusts: empty when it is unknown, its lease expired, its prefix is
    /// contested or pinned (`participant_ips` learn no locators). For a
    /// quarantine target use [`BindingTable::quarantine_locators`].
    pub fn spdp_unicast(&self, prefix: &GuidPrefix, now: Instant) -> Vec<SocketAddr> {
        if self.contested.contains(prefix) {
            return Vec::new();
        }
        match self.entries.get(prefix) {
            Some(e) if !e.expired(now) => e.unicast.clone(),
            _ => Vec::new(),
        }
    }

    /// The locators agentd hands the executor for a quarantine of `prefix`:
    /// [`BindingTable::quarantine_target`]'s `locators`.
    pub fn quarantine_locators(&self, prefix: &GuidPrefix, now: Instant) -> Vec<SocketAddr> {
        self.quarantine_target(prefix, now).locators
    }

    /// What agentd may hand the executor for a quarantine of `prefix`
    /// (module docs, "Quarantine locators"). Candidates are the unicast
    /// locators of the prefix's own last trusted SPDP, live or remembered
    /// for [`LOCATOR_RETENTION`]. A candidate is handed out only when the
    /// prefix was **observed sending from its address** (SPDP source, or an
    /// accepted endpoint announcement), it is not loopback, not pinned to
    /// another prefix, not announced by a profiled participant, and no
    /// other participant was seen at that address announcing the same
    /// ip:port (live, or later than this prefix); one address family only.
    /// Every left-out locator is listed with its reason. None at all for a
    /// contested or pinned prefix.
    pub fn quarantine_target(&self, prefix: &GuidPrefix, now: Instant) -> QuarantineTarget {
        let pinned = self.opts.participant_ips.contains_key(prefix);
        let contested = self.contested.contains(prefix);
        let profiled = self.profiled.contains(prefix);
        let mut t = QuarantineTarget {
            known: pinned || contested || profiled,
            ..QuarantineTarget::default()
        };
        if pinned || contested {
            return t;
        }
        let remembered = self
            .history
            .get(prefix)
            .filter(|h| now.saturating_duration_since(h.at) <= LOCATOR_RETENTION);
        let (cands, sources, forgot): (&[SocketAddr], Vec<IpAddr>, bool) = match remembered {
            Some(h) => (&h.unicast, h.sources.iter().copied().collect(), h.forgot),
            None => match self.entries.get(prefix).filter(|e| !e.expired(now)) {
                Some(e) => (&e.unicast, e.bound_ips.iter().copied().collect(), e.forgot),
                None => return t,
            },
        };
        t.known = true;
        t.guid_only = !profiled;
        t.evidence_truncated = forgot;
        self.filter_candidates(prefix, cands, &sources, &mut t);
        t
    }

    /// [`BindingTable::quarantine_target`] for locators of a prefix this
    /// table does not know, announced by another input (agentd's
    /// `ros2_participant_discovered` events): the same filters, with the
    /// event's source address as the only observed evidence. A prefix the
    /// table knows gets the table's own answer (the other input never
    /// overrides it).
    pub fn vouch_external(
        &self,
        prefix: &GuidPrefix,
        cands: &[SocketAddr],
        src: Option<IpAddr>,
        now: Instant,
    ) -> QuarantineTarget {
        let own = self.quarantine_target(prefix, now);
        if own.known {
            return own;
        }
        let mut t = QuarantineTarget {
            known: true,
            guid_only: true,
            ..QuarantineTarget::default()
        };
        let sources: Vec<IpAddr> = src.map(canonical_ip).into_iter().collect();
        self.filter_candidates(prefix, cands, &sources, &mut t);
        t
    }

    fn filter_candidates(
        &self,
        prefix: &GuidPrefix,
        cands: &[SocketAddr],
        sources: &[IpAddr],
        t: &mut QuarantineTarget,
    ) {
        // Review R2-5 / R3-6: a non-profiled target never gets any port of
        // a **commissioned** host of a profiled participant (pins, identity
        // ips). A profiled target is the robot's own: only its siblings'
        // exact ip:ports are left out.
        let profiled = self.profiled.contains(prefix);
        let commissioned = self.commissioned_host_ips(prefix);
        let host = |ip: IpAddr| {
            if self.is_local(ip) {
                Some(excluded::THIS_HOST)
            } else {
                commissioned
                    .contains(&ip)
                    .then_some(excluded::PROFILED_HOST)
            }
        };
        for l in cands {
            let ip = canonical_ip(l.ip());
            let l = SocketAddr::new(ip, l.port());
            let why = if ip.is_loopback() {
                Some(excluded::LOOPBACK)
            } else if !sources.contains(&ip) {
                Some(excluded::NOT_OBSERVED)
            } else {
                self.claimed_by_other(prefix, &l)
                    .or_else(|| if profiled { None } else { host(ip) })
            };
            match why {
                Some(w) => t.excluded.push((l, w)),
                None if !t.locators.contains(&l) => t.locators.push(l),
                None => {}
            }
        }
        // Review R3-1: the observed source addresses, cut whole by the
        // executor (any source port to the robot's DDS ports): never this
        // host, a pinned address of another prefix, or any address a
        // profiled participant other than the target is known at
        // (commissioned or learned: a whole-address drop there could cut
        // the robot's own participants).
        let learned = self.learned_profiled_ips(prefix);
        let mut seen: Vec<IpAddr> = Vec::new();
        for ip in sources.iter().map(|ip| canonical_ip(*ip)) {
            if seen.contains(&ip) {
                continue;
            }
            seen.push(ip);
            let why = if ip.is_loopback() {
                Some(excluded::LOOPBACK)
            } else if self
                .opts
                .participant_ips
                .iter()
                .any(|(p, ips)| p != prefix && ips.contains(&ip))
            {
                Some(excluded::PINNED_ELSEWHERE)
            } else if let Some(w) = host(ip) {
                Some(w)
            } else if self.identity_ips.contains(&ip) {
                Some(excluded::IDENTITY_HOST)
            } else if learned.contains(&ip) {
                Some(excluded::LEARNED_PROFILED_HOST)
            } else {
                None
            };
            match why {
                Some(w) => t.excluded_addresses.push((ip, w)),
                None => t.addresses.push(ip),
            }
        }
        // One address family (the executor refuses a mix): IPv4 if any.
        if t.locators.iter().any(SocketAddr::is_ipv4) || t.addresses.iter().any(IpAddr::is_ipv4) {
            let (keep, drop): (Vec<SocketAddr>, Vec<SocketAddr>) =
                t.locators.iter().partition(|l| l.is_ipv4());
            t.locators = keep;
            t.excluded
                .extend(drop.into_iter().map(|l| (l, excluded::OTHER_FAMILY)));
            let (keep, drop): (Vec<IpAddr>, Vec<IpAddr>) =
                t.addresses.iter().partition(|a| a.is_ipv4());
            t.addresses = keep;
            t.excluded_addresses
                .extend(drop.into_iter().map(|a| (a, excluded::OTHER_FAMILY)));
        }
    }

    /// Does a participant other than `prefix` claim locator `l` (see
    /// [`BindingTable::quarantine_target`])? Pinned to another prefix, or
    /// announced by a profiled participant (live or remembered). Another
    /// unprofiled prefix seen at the same address announcing the same
    /// ip:port does **not** take it away (review R2-3): both were seen
    /// sending from that host, so they share it, whether it is the rogue's
    /// own second prefix (a self-decoy) or its successor on the port.
    fn claimed_by_other(&self, prefix: &GuidPrefix, l: &SocketAddr) -> Option<&'static str> {
        let ip = l.ip();
        if self
            .opts
            .participant_ips
            .iter()
            .any(|(p, ips)| p != prefix && ips.contains(&ip))
        {
            return Some(excluded::PINNED_ELSEWHERE);
        }
        let announces = |u: &[SocketAddr]| {
            u.iter()
                .any(|x| canonical_ip(x.ip()) == ip && x.port() == l.port())
        };
        // The robot's own: a profiled participant's live or remembered
        // locators (its history is never written by a foreign host).
        let profiled_claims = self.profiled.iter().any(|p| {
            p != prefix
                && (self.history.get(p).is_some_and(|h| announces(&h.unicast))
                    || self.entries.get(p).is_some_and(|e| announces(&e.unicast)))
        });
        profiled_claims.then_some(excluded::PROFILED)
    }

    /// The **pinned** addresses of the robot's own computers (reviews R2-5,
    /// R3-6): the pins of every profiled prefix other than `except`.
    /// Nothing an SPDP can write: an attacker that announces a profiled
    /// prefix first (before the real participant, or after its evidence
    /// lapsed) is bound first-come, and its address must not shield its
    /// other participants. (This host's own addresses, and for whole-address
    /// drops the profile identities' `ips`, are checked besides.)
    fn commissioned_host_ips(&self, except: &GuidPrefix) -> BTreeSet<IpAddr> {
        let mut out = BTreeSet::new();
        for p in self.profiled.iter().filter(|p| *p != except) {
            if let Some(pins) = self.opts.participant_ips.get(p) {
                out.extend(pins.iter().copied());
            }
        }
        out.retain(|ip| !ip.is_loopback());
        out
    }

    /// The addresses profiled participants other than `except` were
    /// **learned** at: their remembered evidence and announced locator
    /// addresses, and the bound source addresses of their live bindings
    /// (contested ones included). Never cut whole (it may be the robot's
    /// computer), but no longer a reason to leave a non-profiled target's
    /// own locators there out (review R3-6). Small: the profile's
    /// participants times the per-entry caps.
    fn learned_profiled_ips(&self, except: &GuidPrefix) -> BTreeSet<IpAddr> {
        let mut out = BTreeSet::new();
        for p in self.profiled.iter().filter(|p| *p != except) {
            if let Some(h) = self.history.get(p) {
                out.extend(h.sources.iter().copied());
                out.extend(h.unicast.iter().map(|l| canonical_ip(l.ip())));
            }
            if let Some(e) = self.entries.get(p) {
                out.extend(e.bound_ips.iter().copied());
                out.extend(e.locator_ips.iter().copied());
            }
        }
        out.retain(|ip| !ip.is_loopback());
        out
    }

    fn history_key(p: GuidPrefix, h: &LastLocators) -> (Rank, Instant, GuidPrefix) {
        (h.rank, h.at, p)
    }

    fn unindex_history(&mut self, p: GuidPrefix, h: &LastLocators) {
        let k = Self::history_key(p, h);
        if let Some(b) = self.history_by_source.get_mut(&h.bucket) {
            b.remove(&k);
            if b.is_empty() {
                self.history_by_source.remove(&h.bucket);
            }
        }
    }

    fn index_history(&mut self, p: GuidPrefix, h: &LastLocators) {
        let k = Self::history_key(p, h);
        self.history_by_source
            .entry(h.bucket)
            .or_default()
            .insert(k);
    }

    fn forget(&mut self, victim: GuidPrefix) {
        if let Some(h) = self.history.remove(&victim) {
            self.unindex_history(victim, &h);
            self.stats.locators_forgotten += 1;
        }
    }

    /// Remember `p`'s unicast locators from a trusted SPDP sent from `src`
    /// (`None`: relayed by a discovery server). `fresh`: a new owner (the
    /// prefix was re-bound after its lease ran out), whose evidence
    /// replaces the old one, unless the prefix is ranked High or above
    /// (it raised a High / Critical finding, or a SOC named it): then the
    /// evidence, locators and rank are **merged** (review R2-3: a rogue
    /// re-announcing its prefix from a second address after its lease does
    /// not wipe the first one; bounded by [`MAX_BOUND_IPS`] sources and
    /// [`MAX_LOCATOR_IPS`] locators, the newest kept). A set without
    /// locators keeps the previous one.
    fn remember(
        &mut self,
        p: GuidPrefix,
        unicast: &[SocketAddr],
        src: Option<IpAddr>,
        fresh: bool,
        now: Instant,
    ) {
        if unicast.is_empty() {
            if let Some(ip) = src {
                self.note_evidence(&p, ip);
            }
            return;
        }
        let old = self.history.remove(&p);
        if let Some(o) = &old {
            self.unindex_history(p, o);
        }
        let floor = if self.profiled.contains(&p) {
            Rank::Profiled
        } else {
            Rank::SpdpOnly
        };
        let mut h = match old {
            Some(o) if !fresh => LastLocators {
                unicast: unicast.to_vec(),
                at: now,
                rank: o.rank.max(floor),
                ..o
            },
            Some(o) if o.rank >= Rank::High => {
                self.stats.evidence_merged += 1;
                let mut merged = unicast.to_vec();
                let mut forgot = o.forgot;
                for l in &o.unicast {
                    if merged.contains(l) {
                        continue;
                    }
                    if merged.len() >= MAX_LOCATOR_IPS {
                        forgot = true;
                        break;
                    }
                    merged.push(*l);
                }
                LastLocators {
                    unicast: merged,
                    at: now,
                    rank: o.rank.max(floor),
                    forgot,
                    ..o
                }
            }
            _ => LastLocators {
                unicast: unicast.to_vec(),
                sources: VecDeque::new(),
                at: now,
                rank: floor,
                bucket: src,
                forgot: false,
            },
        };
        if let Some(ip) = src {
            h.add_source(ip);
        }
        // Per source first: a spray from one address pushes out only its
        // own, lowest rank first. Profiled participants are never counted.
        if h.rank < Rank::Profiled {
            loop {
                let victim = self.history_by_source.get(&h.bucket).and_then(|b| {
                    (b.len() >= MAX_LOCATOR_HISTORY_PER_SOURCE)
                        .then(|| b.first().map(|k| k.2))
                        .flatten()
                });
                match victim {
                    Some(v)
                        if self
                            .history
                            .get(&v)
                            .is_some_and(|x| x.rank < Rank::Profiled) =>
                    {
                        self.forget(v)
                    }
                    _ => break,
                }
            }
        }
        // Global pressure (review R2-4): evict from the fullest per-source
        // bucket, lowest rank then oldest first, so a spray from N
        // addresses pushes out its own entries before a lone rogue's.
        // Profiled entries are never evicted, SOC-named ones only for
        // another SOC-named one; if nothing may go, `p` is not remembered.
        while self.history.len() >= MAX_LOCATOR_HISTORY {
            let victim = self
                .history_by_source
                .values()
                .filter_map(|b| {
                    b.iter()
                        .find(|k| {
                            k.0 < Rank::Profiled
                                && (k.0 < Rank::SocReferenced || h.rank >= Rank::SocReferenced)
                        })
                        .map(|k| (b.len(), *k))
                })
                .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
                .map(|(_, k)| k.2);
            match victim {
                Some(v) => self.forget(v),
                None => {
                    self.stats.locators_not_remembered += 1;
                    return;
                }
            }
        }
        self.index_history(p, &h);
        self.history.insert(p, h);
    }

    /// `ip` was seen sending for `p` (an accepted, non-relayed SPDP or
    /// endpoint announcement): evidence for its locators on that address.
    fn note_evidence(&mut self, p: &GuidPrefix, ip: IpAddr) {
        if let Some(h) = self.history.get_mut(p) {
            h.add_source(ip);
        }
    }

    /// Raise `p`'s eviction rank to at least `rank` (it never drops).
    fn raise_rank(&mut self, p: &GuidPrefix, rank: Rank) {
        let Some(h) = self.history.get(p) else {
            return;
        };
        if h.rank >= rank {
            return;
        }
        let Some(mut h) = self.history.remove(p) else {
            return;
        };
        self.unindex_history(*p, &h);
        h.rank = rank;
        self.index_history(*p, &h);
        self.history.insert(*p, h);
    }

    /// `p` raised a finding of `severity` (the pipeline calls this): a
    /// High or Critical one keeps its remembered locators longer under a
    /// prefix flood (review M6).
    pub fn note_finding(&mut self, p: &GuidPrefix, severity: Severity) {
        match severity {
            Severity::Critical => self.raise_rank(p, Rank::Critical),
            Severity::High => self.raise_rank(p, Rank::High),
            _ => {}
        }
    }

    /// A SOC request named `p` (agentd calls this for `quarantine_node`):
    /// its remembered locators outlast every prefix that was not named
    /// (bounded by [`MAX_LOCATOR_HISTORY`] like the rest).
    pub fn note_soc_reference(&mut self, p: &GuidPrefix) {
        self.raise_rank(p, Rank::SocReferenced);
    }

    /// The eviction rank of `p`'s remembered locators, if any (tests,
    /// status).
    pub fn locator_rank(&self, p: &GuidPrefix) -> Option<Rank> {
        self.history.get(p).map(|h| h.rank)
    }

    /// Is `p` one of the robot's own: profiled or pinned?
    pub fn is_protected(&self, p: &GuidPrefix) -> bool {
        self.profiled.contains(p) || self.opts.participant_ips.contains_key(p)
    }

    /// `p` announced an endpoint from `ip`, accepted by its binding: its
    /// remembered locators are evicted after those of SPDP-only prefixes,
    /// and `ip` (unless relayed) is evidence.
    fn mark_active(&mut self, p: &GuidPrefix, ip: Option<IpAddr>) {
        self.raise_rank(p, Rank::Active);
        if let Some(ip) = ip {
            self.note_evidence(p, ip);
        }
    }

    /// A profiled prefix with no live binding announced from `ip`, which
    /// its remembered evidence never saw (neither a source nor a locator
    /// address, nor same-host loopback for a same-host participant): a
    /// foreign host (review H1).
    fn foreign_to_profiled(
        &self,
        p: &GuidPrefix,
        ip: IpAddr,
        ingress: Ingress,
        now: Instant,
    ) -> bool {
        if !self.profiled.contains(p) || self.entries.get(p).is_some_and(|e| !e.expired(now)) {
            return false;
        }
        let Some(h) = self
            .history
            .get(p)
            .filter(|h| now.saturating_duration_since(h.at) <= LOCATOR_RETENTION)
        else {
            return false;
        };
        let local = h
            .sources
            .iter()
            .copied()
            .chain(h.unicast.iter().map(|l| canonical_ip(l.ip())))
            .any(|x| self.is_local(x));
        !(h.knows(ip) || (self.same_host_loopback(ip, ingress) && local))
    }

    /// Is `prefix` contested (a profiled, unpinned prefix claimed by SPDP
    /// from more than one host)? Its every source is untrusted until it is
    /// pinned. See the module docs.
    pub fn is_contested(&self, prefix: &GuidPrefix) -> bool {
        self.contested.contains(prefix) && !self.opts.participant_ips.contains_key(prefix)
    }

    /// Every contested prefix (see [`BindingTable::is_contested`]).
    pub fn contested(&self) -> impl Iterator<Item = &GuidPrefix> {
        self.contested
            .iter()
            .filter(|p| !self.opts.participant_ips.contains_key(*p))
    }

    /// The source IPs currently trusted for **profiled** participants: their
    /// pins, and the bound SPDP source / locator IPs of live, uncontested
    /// learned entries. For consumers that want to tell known robot
    /// addresses from fresh ones (e.g. correlation-state protection). Small:
    /// bounded by the profile's participants times the per-entry caps.
    pub fn profiled_ips(&self, now: Instant) -> BTreeSet<IpAddr> {
        let mut out = BTreeSet::new();
        for p in &self.profiled {
            if let Some(pins) = self.opts.participant_ips.get(p) {
                out.extend(pins.iter().copied());
                continue;
            }
            if self.contested.contains(p) {
                continue;
            }
            if let Some(e) = self.entries.get(p).filter(|e| !e.expired(now)) {
                out.extend(e.bound_ips.iter().chain(&e.locator_ips).copied());
            }
        }
        out
    }

    /// Would `ip` be accepted as a source for `prefix`, ingress unknown?
    /// `None` = no binding. See [`BindingTable::allows_from`].
    pub fn allows(&self, prefix: &GuidPrefix, ip: IpAddr) -> Option<bool> {
        self.allows_from(prefix, ip, Ingress::Unknown)
    }

    /// Would `ip`, received with `ingress`, be accepted as a source for
    /// `prefix`? `None` = no binding. A loopback source on a non-loopback
    /// interface is never accepted; one on loopback is accepted for a
    /// same-host participant (module docs). A contested prefix (unless
    /// pinned) accepts no source: `Some(false)`.
    pub fn allows_from(&self, prefix: &GuidPrefix, ip: IpAddr, ingress: Ingress) -> Option<bool> {
        let ip = canonical_ip(ip);
        if self.spoofed_loopback(ip, ingress) {
            return self.is_bound(prefix).then_some(false);
        }
        let same_host = self.same_host_loopback(ip, ingress);
        if let Some(pins) = self.opts.participant_ips.get(prefix) {
            return Some(
                pins.contains(&ip) || (same_host && pins.iter().any(|p| self.is_local(*p))),
            );
        }
        if self.contested.contains(prefix) {
            return Some(false);
        }
        self.entries
            .get(prefix)
            .map(|e| e.allows(ip) || (same_host && self.entry_is_local(e)))
    }

    /// This host's addresses known to the table (configured, detected and
    /// learned from loopback traffic), loopback addresses excluded.
    pub fn local_addresses(&self) -> &[IpAddr] {
        &self.local
    }

    /// Is `ip` this host's: a loopback address or a known local address?
    pub fn is_local(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        ip.is_loopback() || self.local.contains(&ip)
    }

    fn entry_is_local(&self, e: &Entry) -> bool {
        e.bound_ips
            .iter()
            .chain(&e.locator_ips)
            .any(|ip| self.is_local(*ip))
    }

    /// A loopback source received on a non-loopback interface: forged.
    fn spoofed_loopback(&self, ip: IpAddr, ingress: Ingress) -> bool {
        ingress == Ingress::External && ip.is_loopback()
    }

    /// A loopback source that is attributed to this host.
    fn same_host_loopback(&self, ip: IpAddr, ingress: Ingress) -> bool {
        ip.is_loopback()
            && match ingress {
                Ingress::Loopback => true,
                Ingress::Unknown => !self.opts.strict_loopback_ingress,
                Ingress::External => false,
            }
    }

    /// A non-loopback source seen on the loopback interface is one of this
    /// host's own addresses (only the host can send on `lo`): learn it.
    fn learn_local(&mut self, ip: IpAddr, ingress: Ingress) {
        if ingress == Ingress::Loopback
            && !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !self.local.contains(&ip)
            && self.local.len() < MAX_LOCAL_ADDRESSES
        {
            self.local.push(ip);
            self.stats.local_learned += 1;
        }
    }

    fn trusted_relay(&self, ip: IpAddr, ingress: Ingress) -> bool {
        self.opts.discovery_servers.contains(&ip)
            || (self.same_host_loopback(ip, ingress)
                && self
                    .opts
                    .discovery_servers
                    .iter()
                    .any(|s| self.is_local(*s)))
    }

    fn judge(
        &mut self,
        participant: &GuidPrefix,
        ip: IpAddr,
        ingress: Ingress,
        relayed: bool,
        conflict: bool,
    ) -> Verdict {
        if self.spoofed_loopback(ip, ingress) {
            self.stats.spoofed_loopback += 1;
            return Verdict::Mismatch(Mismatch::SpoofedLoopback);
        }
        if self.is_contested(participant) {
            return Verdict::Mismatch(Mismatch::Contested);
        }
        if relayed || conflict {
            if self.trusted_relay(ip, ingress) {
                return Verdict::Ok;
            }
            return Verdict::Mismatch(if relayed {
                Mismatch::Relayed
            } else {
                Mismatch::GuidConflict
            });
        }
        let pinned = self.opts.participant_ips.contains_key(participant);
        match self.allows_from(participant, ip, ingress) {
            Some(true) => {
                let direct = self
                    .opts
                    .participant_ips
                    .get(participant)
                    .map(|p| p.contains(&ip))
                    .or_else(|| self.entries.get(participant).map(|e| e.allows(ip)))
                    .unwrap_or(false);
                if !direct {
                    self.stats.same_host_loopback += 1;
                }
                Verdict::Ok
            }
            Some(false) if pinned => Verdict::Mismatch(Mismatch::NotPinned),
            Some(false) => Verdict::Mismatch(Mismatch::NotBound),
            None => Verdict::Unbound,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mismatch_finding(
        &mut self,
        profile: &Profile,
        participant: &GuidPrefix,
        kind: EndpointKind,
        topic: &str,
        ip: IpAddr,
        why: Mismatch,
        ambiguous: bool,
    ) -> BindingFinding {
        self.stats.endpoint_mismatches += 1;
        let severity = if matches!(why, Mismatch::SpoofedLoopback | Mismatch::Contested)
            || motion_capable_writer(profile, kind, topic, ambiguous)
        {
            Severity::Critical
        } else {
            Severity::High
        };
        let topic = clip_name(topic);
        let amb = if ambiguous {
            " (ambiguous announcement: conflicting duplicate parameters, the topic may differ)"
        } else {
            ""
        };
        let profiled = if self.profiled.contains(participant) {
            "profiled "
        } else {
            ""
        };
        let detail = format!(
            "{} on {topic} attributed to {profiled}participant {} was announced from {ip}, {}{amb}",
            kind_str(kind),
            hex12(participant),
            why.text()
        );
        (
            Deviation::new(rules::ENDPOINT_SOURCE_MISMATCH, severity, detail),
            ip.to_string(),
            Some(*participant),
        )
    }

    /// Medium; High for a writer that could command motion (see
    /// [`motion_capable_writer`]) — the profile has already accepted it if
    /// it is attributed to a profiled participant.
    fn unannounced_finding(&mut self, profile: &Profile, h: &Held, why: &str) -> BindingFinding {
        let severity = if motion_capable_writer(profile, h.kind, &h.topic, h.ambiguous) {
            Severity::High
        } else {
            Severity::Medium
        };
        let profiled = if self.profiled.contains(&h.participant) {
            "profiled "
        } else {
            ""
        };
        let detail = format!(
            "{} on {} attributed to {profiled}participant {} was announced from {} but that \
             participant never announced itself (no SPDP {why})",
            kind_str(h.kind),
            clip_name(&h.topic),
            hex12(&h.participant),
            h.src_ip
        );
        (
            Deviation::new(rules::ENDPOINT_UNANNOUNCED_PARTICIPANT, severity, detail),
            h.src_ip.to_string(),
            Some(h.participant),
        )
    }

    /// Learn from (or judge) one SPDP announcement.
    /// `ingress`: see [`Ingress`] (a loopback source on a non-loopback
    /// interface is rejected as forged, Critical).
    pub fn observe_spdp(
        &mut self,
        profile: &Profile,
        spdp: &SpdpInfo,
        src_ip: Option<IpAddr>,
        ingress: Ingress,
        now: Instant,
        out: &mut Vec<BindingFinding>,
    ) {
        if !self.opts.enabled {
            return;
        }
        let Some(ip) = src_ip.map(canonical_ip) else {
            self.stats.unparsed_src_ip += 1;
            return;
        };
        self.learn_local(ip, ingress);
        let p = spdp.guid_prefix;
        let locators: Vec<IpAddr> = {
            let mut v: Vec<IpAddr> = Vec::new();
            for l in spdp.metatraffic_unicast.iter().chain(&spdp.default_unicast) {
                if let Some(ip) = locator_ip(l) {
                    if !v.contains(&ip) && v.len() < MAX_LOCATOR_IPS {
                        v.push(ip);
                    }
                }
            }
            v
        };
        // More distinct unicast locators than are kept: a quarantine of
        // the prefix can never be `full` (review R3-1).
        let mut over = false;
        let unicast: Vec<SocketAddr> = {
            let mut v: Vec<SocketAddr> = Vec::new();
            for l in spdp.metatraffic_unicast.iter().chain(&spdp.default_unicast) {
                let port = u16::try_from(l.port).ok().filter(|p| *p != 0);
                if let (Some(ip), Some(port)) = (locator_ip(l), port) {
                    let sa = SocketAddr::new(ip, port);
                    if v.contains(&sa) {
                        continue;
                    }
                    if v.len() < MAX_LOCATOR_IPS {
                        v.push(sa);
                    } else {
                        over = true;
                    }
                }
            }
            v
        };
        let lease = spdp
            .lease_duration
            .and_then(|d| d.to_std())
            .unwrap_or(DEFAULT_LEASE)
            .clamp(MIN_LEASE, MAX_LEASE);

        let reject = |this: &mut Self, why: &str, out: &mut Vec<BindingFinding>| {
            this.stats.spdp_mismatches += 1;
            let profiled = this.profiled.contains(&p);
            let severity = if this.spoofed_loopback(ip, ingress) || this.is_contested(&p) {
                Severity::Critical
            } else if profiled {
                Severity::High
            } else {
                Severity::Medium
            };
            let detail = format!(
                "SPDP announcement for {}participant {} from {ip} {why}; not learned",
                if profiled { "profiled " } else { "" },
                hex12(&p)
            );
            out.push((
                Deviation::new(rules::PARTICIPANT_SOURCE_MISMATCH, severity, detail),
                ip.to_string(),
                Some(p),
            ));
        };

        if self.spoofed_loopback(ip, ingress) {
            self.stats.spoofed_loopback += 1;
            reject(
                self,
                "is a loopback source address received on a non-loopback interface (forged source)",
                out,
            );
            return;
        }

        if spdp.relayed() {
            if !self.trusted_relay(ip, ingress) {
                reject(
                    self,
                    "was relayed by another participant from an IP that is not a configured discovery server",
                    out,
                );
                return;
            }
            // Trusted relay: learn the locators only, never the server's IP.
            if self.opts.participant_ips.contains_key(&p) {
                return;
            }
            // A profiled prefix with no live binding relayed with locators
            // none of which it was ever seen on: a foreign host (H1).
            if !locators.is_empty()
                && locators
                    .iter()
                    .all(|l| self.foreign_to_profiled(&p, *l, Ingress::Unknown, now))
            {
                self.contest_foreign(p, out, &reject);
                return;
            }
            self.remember(p, &unicast, None, false, now);
            match self.entries.get_mut(&p) {
                Some(e) => {
                    let old = e.last_refresh;
                    e.locator_ips = locators;
                    e.unicast = unicast;
                    e.last_refresh = now;
                    e.lease = lease;
                    self.stats.refreshed += 1;
                    self.reindex(p, Some(old), Some(now));
                }
                None => {
                    self.insert(
                        p,
                        Entry {
                            bound_ips: VecDeque::new(),
                            locator_ips: locators,
                            unicast,
                            last_refresh: now,
                            lease,
                            forgot: false,
                        },
                    );
                    self.stats.learned += 1;
                }
            }
            if over {
                self.mark_forgot(&p);
            }
            self.resolve_held(profile, &p, out);
            return;
        }

        if self.opts.participant_ips.contains_key(&p) {
            if self.allows_from(&p, ip, ingress) != Some(true) {
                reject(self, "which is not one of its pinned participant_ips", out);
                return;
            }
            self.resolve_held(profile, &p, out);
            return;
        }

        if self.contested.contains(&p) {
            reject(
                self,
                "but its GUID prefix is contested (announced from more than one host); no source \
                 is trusted for it until it is pinned in participant_ips",
                out,
            );
            return;
        }

        // Review H1: a foreign host never takes over a profiled prefix's
        // remembered locators, even after its lease ran out.
        if self.foreign_to_profiled(&p, ip, ingress, now) {
            self.contest_foreign(p, out, &reject);
            return;
        }
        let allowed = self.allows_from(&p, ip, ingress) == Some(true);
        let accepted = match self.entries.get(&p) {
            Some(e) => allowed || e.expired(now),
            None => true,
        };
        if accepted {
            // A new owner (re-bound after its lease ran out, or after it
            // left, from an address it was never seen on): its evidence
            // replaces the old one.
            let fresh = !allowed && !self.history.get(&p).is_some_and(|h| h.knows(ip));
            self.remember(p, &unicast, Some(ip), fresh, now);
        }
        match self.entries.get_mut(&p) {
            Some(e) if allowed => {
                let old = e.last_refresh;
                e.add_bound(ip);
                e.locator_ips = locators;
                e.unicast = unicast;
                e.last_refresh = now;
                e.lease = lease;
                self.stats.refreshed += 1;
                self.reindex(p, Some(old), Some(now));
            }
            Some(e) if !e.expired(now) => {
                if self.profiled.contains(&p) {
                    // Two hosts claim a profiled prefix: neither is trusted
                    // (the first one is not more credible than the second).
                    self.contested.insert(p);
                    self.stats.contested += 1;
                    reject(
                        self,
                        "which is outside its current binding: another host claims its GUID \
                         prefix, which is now contested (no source is trusted for it, the bound \
                         one included, until it is pinned in participant_ips)",
                        out,
                    );
                } else {
                    reject(
                        self,
                        "which is outside its current binding (another host claims its GUID prefix)",
                        out,
                    );
                }
                return;
            }
            Some(e) => {
                // Lease expired: the old participant is gone, re-bind.
                let old = e.last_refresh;
                e.bound_ips.clear();
                e.forgot = false;
                e.add_bound(ip);
                e.locator_ips = locators;
                e.unicast = unicast;
                e.last_refresh = now;
                e.lease = lease;
                self.stats.rebound += 1;
                self.reindex(p, Some(old), Some(now));
            }
            None => {
                let mut e = Entry {
                    bound_ips: VecDeque::new(),
                    locator_ips: locators,
                    unicast,
                    last_refresh: now,
                    lease,
                    forgot: false,
                };
                e.add_bound(ip);
                self.insert(p, e);
                self.stats.learned += 1;
            }
        }
        if over {
            self.mark_forgot(&p);
        }
        self.resolve_held(profile, &p, out);
    }

    /// Some of `p`'s announced locators were not kept.
    fn mark_forgot(&mut self, p: &GuidPrefix) {
        if let Some(h) = self.history.get_mut(p) {
            h.forgot = true;
        }
        if let Some(e) = self.entries.get_mut(p) {
            e.forgot = true;
        }
    }

    /// Review H1: `p` (profiled, no live binding) was announced from a host
    /// its remembered evidence never saw. It becomes contested (no source
    /// is trusted for it until it is pinned), its remembered locators are
    /// kept, and a Critical `participant_source_mismatch` is raised.
    fn contest_foreign(
        &mut self,
        p: GuidPrefix,
        out: &mut Vec<BindingFinding>,
        reject: &dyn Fn(&mut Self, &str, &mut Vec<BindingFinding>),
    ) {
        self.contested.insert(p);
        self.stats.contested += 1;
        self.stats.foreign_rebinds += 1;
        reject(
            self,
            "after its lease ran out (or it left), from a host it was never seen on: another host \
             claims its GUID prefix, which is now contested (no source is trusted for it until it \
             is pinned in participant_ips; its last locators are kept)",
            out,
        );
    }

    /// Keep the eviction index in step with an entry's `last_refresh`.
    fn reindex(&mut self, p: GuidPrefix, old: Option<Instant>, new: Option<Instant>) {
        let profiled = self.profiled.contains(&p);
        if let Some(old) = old {
            self.order.remove(&(profiled, old, p));
        }
        if let Some(new) = new {
            self.order.insert((profiled, new, p));
        }
    }

    /// Remove a learned entry (and its index key).
    fn remove_entry(&mut self, p: &GuidPrefix) -> bool {
        match self.entries.remove(p) {
            Some(e) => {
                self.reindex(*p, Some(e.last_refresh), None);
                true
            }
            None => false,
        }
    }

    fn insert(&mut self, p: GuidPrefix, e: Entry) {
        let last = e.last_refresh;
        if let Some(old) = self.entries.get(&p).map(|o| o.last_refresh) {
            self.reindex(p, Some(old), None);
        }
        while self.entries.len() >= self.opts.max_participants && !self.entries.contains_key(&p) {
            // Oldest unprofiled first (`false` sorts first); only then the
            // oldest profiled one. O(log n).
            let Some((_, _, victim)) = self.order.pop_first() else {
                break;
            };
            if self.entries.remove(&victim).is_some() {
                self.stats.evicted += 1;
            }
        }
        self.entries.insert(p, e);
        self.reindex(p, None, Some(last));
    }

    /// An SPDP dispose / unregister. Returns `Some(true)` if it came from an
    /// IP bound to the participant (binding removed), `Some(false)` if from
    /// an IP outside the binding (binding kept), `None` if not bound / not
    /// judged.
    pub fn observe_participant_removal(
        &mut self,
        r: &ParticipantRemoval,
        src_ip: Option<IpAddr>,
        ingress: Ingress,
    ) -> Option<bool> {
        if !self.opts.enabled {
            return None;
        }
        let ip = canonical_ip(src_ip?);
        let p = r.guid_prefix;
        if self.spoofed_loopback(ip, ingress) {
            self.stats.spoofed_loopback += 1;
            return self.is_bound(&p).then_some(false);
        }
        if r.source != p && self.trusted_relay(ip, ingress) {
            if self.remove_entry(&p) {
                self.stats.removed += 1;
            }
            return Some(true);
        }
        let allowed = self.allows_from(&p, ip, ingress)?;
        if allowed && self.remove_entry(&p) {
            self.stats.removed += 1;
        }
        Some(allowed)
    }

    /// Judge one SEDP endpoint announcement. Unbound participants are held.
    /// `ambiguous`: the datagram carried conflicting duplicate identity
    /// parameters (topic / type / GUID), so the parsed topic may not be the
    /// one a DDS stack acts on; a writer is then judged as if it were on a
    /// motion topic (worst case).
    #[allow(clippy::too_many_arguments)]
    pub fn observe_endpoint(
        &mut self,
        profile: &Profile,
        ep: &EndpointInfo,
        src_ip: Option<IpAddr>,
        ingress: Ingress,
        ambiguous: bool,
        now: Instant,
        out: &mut Vec<BindingFinding>,
    ) {
        if !self.opts.enabled {
            return;
        }
        let Some(ip) = src_ip.map(canonical_ip) else {
            self.stats.unparsed_src_ip += 1;
            return;
        };
        self.learn_local(ip, ingress);
        match self.judge(&ep.participant, ip, ingress, ep.relayed(), ep.guid_conflict) {
            Verdict::Ok => {
                let direct = !ep.relayed() && !ep.guid_conflict;
                self.mark_active(&ep.participant, direct.then_some(ip));
            }
            Verdict::Mismatch(why) => {
                let f = self.mismatch_finding(
                    profile,
                    &ep.participant,
                    ep.kind,
                    &ep.topic,
                    ip,
                    why,
                    ambiguous,
                );
                out.push(f);
            }
            Verdict::Unbound => {
                let held = Held {
                    participant: ep.participant,
                    kind: ep.kind,
                    topic: truncate(&ep.topic),
                    src_ip: ip,
                    ingress,
                    // `hold` is clamped to MAX_HOLD; never panic on overflow.
                    deadline: now.checked_add(self.opts.hold).unwrap_or(now),
                    ambiguous,
                };
                if self.opts.hold.is_zero() {
                    self.stats.held_expired += 1;
                    let f = self.unannounced_finding(profile, &held, "was seen before it");
                    out.push(f);
                    return;
                }
                // Only scan the queue when something is held for this
                // participant (O(1) check), so a flood of fresh prefixes
                // costs no queue scans.
                let repeat = if self.held_count.contains_key(&held.participant) {
                    self.held.iter_mut().find(|h| {
                        h.participant == held.participant
                            && h.kind == held.kind
                            && h.src_ip == held.src_ip
                            && h.ingress == held.ingress
                            && h.topic == held.topic
                    })
                } else {
                    None
                };
                if let Some(h) = repeat {
                    // A repeat keeps its first deadline; ambiguity is sticky.
                    h.ambiguous |= held.ambiguous;
                    return;
                }
                if self.held.len() >= self.opts.max_pending {
                    if let Some(old) = self.pop_held() {
                        self.stats.held_overflow += 1;
                        let f = self.unannounced_finding(
                            profile,
                            &old,
                            "was seen before the held-announcement queue overflowed",
                        );
                        out.push(f);
                    }
                }
                self.stats.held += 1;
                *self.held_count.entry(held.participant).or_insert(0) += 1;
                self.held.push_back(held);
            }
        }
    }

    fn pop_held(&mut self) -> Option<Held> {
        let h = self.held.pop_front()?;
        if let Some(n) = self.held_count.get_mut(&h.participant) {
            *n -= 1;
            if *n == 0 {
                self.held_count.remove(&h.participant);
            }
        }
        Some(h)
    }

    /// Re-judge held announcements of `p` now that it has a binding.
    fn resolve_held(&mut self, profile: &Profile, p: &GuidPrefix, out: &mut Vec<BindingFinding>) {
        if self.held_count.remove(p).is_none() {
            return;
        }
        let (mine, rest): (VecDeque<Held>, VecDeque<Held>) =
            self.held.drain(..).partition(|h| h.participant == *p);
        self.held = rest;
        for h in mine {
            self.stats.held_resolved += 1;
            // Held announcements were neither relayed nor conflicting (those
            // are judged at once), so only the binding matters.
            if let Verdict::Mismatch(why) =
                self.judge(&h.participant, h.src_ip, h.ingress, false, false)
            {
                let f = self.mismatch_finding(
                    profile,
                    &h.participant,
                    h.kind,
                    &h.topic,
                    h.src_ip,
                    why,
                    h.ambiguous,
                );
                out.push(f);
            }
        }
    }

    /// Report held announcements whose hold window has passed.
    /// Deadlines are monotonic for a monotonic clock (constant hold), so the
    /// queue is ordered; with a clock that went backwards some entries
    /// expire late, never early, and nothing panics.
    pub fn expire(&mut self, profile: &Profile, now: Instant, out: &mut Vec<BindingFinding>) {
        while self.held.front().is_some_and(|h| h.deadline <= now) {
            if let Some(h) = self.pop_held() {
                self.stats.held_expired += 1;
                let f = self.unannounced_finding(profile, &h, "within the hold window");
                out.push(f);
            }
        }
    }

    /// Report every held announcement now (end of a capture replay).
    pub fn flush(&mut self, profile: &Profile, out: &mut Vec<BindingFinding>) {
        while let Some(h) = self.pop_held() {
            self.stats.held_expired += 1;
            let f = self.unannounced_finding(profile, &h, "before the end of the input");
            out.push(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn prefix_parsing() {
        assert_eq!(parse_prefix("0102030405060708090A0b0c").unwrap()[11], 0x0c);
        for bad in [
            "",
            "01",
            "zz02030405060708090a0b0c",
            "0102030405060708090a0b0c0d",
            "é102030405060708090a0b0",
        ] {
            assert!(parse_prefix(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ip_canonicalisation_and_locators() {
        let mapped: IpAddr = Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped().into();
        assert_eq!(canonical_ip(mapped), IpAddr::from([10, 0, 0, 5]));
        assert_eq!(
            parse_src_ip("::ffff:10.0.0.5"),
            Some(IpAddr::from([10, 0, 0, 5]))
        );
        assert_eq!(parse_src_ip("garbage"), None);
        let mut a = [0u8; 16];
        a[12..].copy_from_slice(&[10, 0, 0, 7]);
        let l = |kind, address| Locator {
            kind,
            port: 7410,
            address,
        };
        assert_eq!(
            locator_ip(&l(LOCATOR_KIND_UDPV4, a)),
            Some(IpAddr::from([10, 0, 0, 7]))
        );
        assert_eq!(locator_ip(&l(LOCATOR_KIND_UDPV4, [0; 16])), None);
        let mut m = [0u8; 16];
        m[12..].copy_from_slice(&[239, 255, 0, 1]);
        assert_eq!(locator_ip(&l(LOCATOR_KIND_UDPV4, m)), None);
        assert_eq!(
            locator_ip(&l(LOCATOR_KIND_UDPV6, Ipv6Addr::LOCALHOST.octets())),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(locator_ip(&l(16, a)), None); // shared memory etc.
    }

    // ---- fixtures -------------------------------------------------------

    const P1: GuidPrefix = [0x11; 12]; // profiled
    const P2: GuidPrefix = [0x22; 12]; // unprofiled
    const RIP: [u8; 4] = [192, 168, 50, 10]; // the robot computer
    const RLOC: [u8; 4] = [192, 168, 60, 10]; // its second interface
    const XIP: [u8; 4] = [192, 168, 50, 66]; // another host
    const DS: [u8; 4] = [10, 0, 0, 2]; // discovery server

    fn ip(a: [u8; 4]) -> IpAddr {
        IpAddr::from(a)
    }

    fn lo4() -> IpAddr {
        IpAddr::from([127, 0, 0, 1])
    }

    fn profile() -> Profile {
        let mut p = Profile {
            model: "t".into(),
            locked: true,
            ..Default::default()
        };
        p.participants.insert(hex12(&P1));
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            robodr_events::profile::Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
                ..Default::default()
            },
        );
        p
    }

    fn loc(a: [u8; 4]) -> Locator {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&a);
        Locator {
            kind: LOCATOR_KIND_UDPV4,
            port: 7410,
            address,
        }
    }

    fn spdp(p: GuidPrefix, locators: &[[u8; 4]], lease_s: Option<i32>) -> SpdpInfo {
        SpdpInfo {
            guid_prefix: p,
            attribution: robodr_rtps::Attribution::ParticipantGuid,
            source: p,
            participant_entity: None,
            protocol_version: None,
            vendor_id: None,
            domain_id: None,
            domain_tag: None,
            entity_name: None,
            user_data: None,
            lease_duration: lease_s.map(|seconds| robodr_rtps::RtpsDuration {
                seconds,
                fraction: 0,
            }),
            metatraffic_unicast: locators.iter().map(|a| loc(*a)).collect(),
            metatraffic_multicast: Vec::new(),
            default_unicast: Vec::new(),
            default_multicast: Vec::new(),
            alternate_guid_prefixes: Vec::new(),
            from_fragments: false,
        }
    }

    fn ep(p: GuidPrefix, kind: EndpointKind, topic: &str) -> EndpointInfo {
        EndpointInfo {
            kind,
            guid: None,
            participant: p,
            attribution: robodr_rtps::Attribution::EndpointGuid,
            source: p,
            participant_guid_param: None,
            guid_conflict: false,
            topic: topic.into(),
            type_name: "t".into(),
            topics: vec![topic.into()],
            type_names: vec!["t".into()],
            alternates: Vec::new(),
            from_fragments: false,
            unicast_locators: Vec::new(),
            multicast_locators: Vec::new(),
        }
    }

    fn writer(p: GuidPrefix) -> EndpointInfo {
        ep(p, EndpointKind::Writer, "rt/cmd_vel")
    }

    fn removal(p: GuidPrefix, source: GuidPrefix) -> ParticipantRemoval {
        ParticipantRemoval {
            guid_prefix: p,
            attribution: robodr_rtps::Attribution::KeyHash,
            source,
            status: robodr_rtps::StatusInfo { raw: [0, 0, 0, 3] },
        }
    }

    struct T {
        b: BindingTable,
        prof: Profile,
        now: Instant,
    }

    impl T {
        fn new(opts: BindingOptions) -> Self {
            let prof = profile();
            Self {
                b: BindingTable::new(opts, &prof),
                prof,
                now: Instant::now(),
            }
        }

        fn local() -> Self {
            Self::new(BindingOptions {
                local_addresses: vec![ip(RIP)],
                ..Default::default()
            })
        }

        fn spdp_in(&mut self, s: &SpdpInfo, src: IpAddr, ing: Ingress) -> Vec<BindingFinding> {
            let mut out = Vec::new();
            self.b
                .observe_spdp(&self.prof, s, Some(src), ing, self.now, &mut out);
            out
        }

        fn spdp(&mut self, s: &SpdpInfo, src: IpAddr) -> Vec<BindingFinding> {
            self.spdp_in(s, src, Ingress::Unknown)
        }

        fn ep_in(&mut self, e: &EndpointInfo, src: IpAddr, ing: Ingress) -> Vec<BindingFinding> {
            let mut out = Vec::new();
            self.b
                .observe_endpoint(&self.prof, e, Some(src), ing, false, self.now, &mut out);
            out
        }

        fn ep(&mut self, e: &EndpointInfo, src: IpAddr) -> Vec<BindingFinding> {
            self.ep_in(e, src, Ingress::Unknown)
        }

        fn advance(&mut self, d: Duration) {
            self.now += d;
        }

        fn expire(&mut self) -> Vec<BindingFinding> {
            let mut out = Vec::new();
            self.b.expire(&self.prof, self.now, &mut out);
            out
        }
    }

    fn one(f: &[BindingFinding], rule: &str, sev: Severity) {
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].0.rule, rule, "{f:#?}");
        assert_eq!(f[0].0.severity, sev, "{f:#?}");
    }

    // ---- pure helpers ---------------------------------------------------

    #[test]
    fn loopback_classification() {
        assert!(is_loopback_ip(lo4()));
        assert!(is_loopback_ip(IpAddr::from([127, 9, 8, 7])));
        assert!(is_loopback_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_loopback_ip(
            Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped().into()
        ));
        assert!(!is_loopback_ip(ip(RIP)));
        assert!(!is_loopback_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert_eq!(Ingress::default(), Ingress::Unknown);
    }

    #[test]
    fn local_address_parsing() {
        let fib = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n  \
                   +-- 127.0.0.0/8 2 0 2\n     |-- 127.0.0.1\n        /32 host LOCAL\n     \
                   |-- 192.168.50.10\n        /32 host LOCAL\n     |-- 192.168.50.255\n        \
                   /32 link BROADCAST\n     |-- 192.168.50.10\n        /32 host LOCAL\n\
                   garbage line\n        /32 host LOCAL\n";
        let v6 = "fe800000000000000000000000000001 02 40 20 80 eth0\n\
                  00000000000000000000000000000001 01 80 10 80 lo\n\
                  zz\n\
                  fd00000000000000000000000000000g 03 40 00 80 bad\n\
                  \n";
        assert_eq!(
            parse_local_addresses(fib, v6),
            vec![ip(RIP), "fe80::1".parse::<IpAddr>().unwrap()]
        );
        assert!(parse_local_addresses("", "").is_empty());
        // An orphan "/32 host LOCAL" with no address before it is ignored.
        assert!(parse_local_addresses("/32 host LOCAL\n", "").is_empty());
        let many: String = (0..200)
            .map(|i| format!("|-- 10.0.{}.{}\n /32 host LOCAL\n", i / 200, i % 200 + 1))
            .collect();
        assert_eq!(parse_local_addresses(&many, "").len(), MAX_LOCAL_ADDRESSES);
        // Whatever the host has, detection never panics nor returns loopback.
        assert!(detect_local_addresses().iter().all(|a| !a.is_loopback()));
    }

    #[test]
    fn motion_topic_detection() {
        let p = profile();
        assert!(is_motion_topic(&p, "rt/cmd_vel"));
        assert!(!is_motion_topic(&p, "rt/odom"));
        assert!(!is_motion_topic(&p, "cmd_vel"), "not a ROS topic name");
        assert!(
            !is_motion_topic(&p, "rq/cmd_velRequest"),
            "service, not topic"
        );
        assert!(!is_motion_topic(&Profile::default(), "rt/cmd_vel"));
        assert!(motion_capable_writer(
            &p,
            EndpointKind::Writer,
            "rt/x",
            true
        ));
        assert!(!motion_capable_writer(
            &p,
            EndpointKind::Reader,
            "rt/cmd_vel",
            true
        ));
        assert!(!motion_capable_writer(
            &Profile::default(),
            EndpointKind::Writer,
            "rt/x",
            true
        ));
    }

    // ---- learning and judging --------------------------------------------

    #[test]
    fn spdp_binds_source_and_locators() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.b.is_empty());
        assert!(t.spdp(&spdp(P1, &[RIP, RLOC], None), ip(RIP)).is_empty());
        assert_eq!(t.b.len(), 1);
        assert!(t.b.is_bound(&P1));
        assert!(!t.b.is_bound(&P2));
        assert_eq!(t.b.allows(&P1, ip(RIP)), Some(true));
        assert_eq!(t.b.allows(&P1, ip(RLOC)), Some(true));
        assert_eq!(
            t.b.allows(&P1, Ipv4Addr::from(RIP).to_ipv6_mapped().into()),
            Some(true)
        );
        assert_eq!(t.b.allows(&P1, ip(XIP)), Some(false));
        assert_eq!(t.b.allows(&P2, ip(RIP)), None);
        // The announced unicast locators with their ports (for the
        // executor's quarantine target); none for an unknown participant.
        assert_eq!(
            t.b.spdp_unicast(&P1, t.now),
            vec![
                SocketAddr::new(ip(RIP), 7410),
                SocketAddr::new(ip(RLOC), 7410)
            ]
        );
        assert!(t.b.spdp_unicast(&P2, t.now).is_empty());
        assert!(t
            .b
            .spdp_unicast(&P1, t.now + Duration::from_secs(3600))
            .is_empty());
        assert!(t.ep(&writer(P1), ip(RIP)).is_empty());
        assert!(t.ep(&writer(P1), ip(RLOC)).is_empty());
        assert_eq!(t.b.stats().learned, 1);
    }

    #[test]
    fn endpoint_mismatch_severities() {
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P1, &[], None), ip(RIP));
        let f = t.ep(&writer(P1), ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert!(f[0].0.detail.contains("profiled participant"));
        assert_eq!(f[0].1, "192.168.50.66");
        let f = t.ep(&ep(P1, EndpointKind::Reader, "rt/cmd_vel"), ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::High);
        let f = t.ep(&ep(P1, EndpointKind::Writer, "rt/odom"), ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::High);
        // Ambiguous: a writer on any topic is judged as a motion writer.
        let mut out = Vec::new();
        t.b.observe_endpoint(
            &t.prof,
            &ep(P1, EndpointKind::Writer, "rt/odom"),
            Some(ip(XIP)),
            Ingress::Unknown,
            true,
            t.now,
            &mut out,
        );
        one(&out, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert!(out[0].0.detail.contains("ambiguous"));
        assert_eq!(t.b.stats().endpoint_mismatches, 4);
    }

    #[test]
    fn hostile_topic_text_is_truncated() {
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P2, &[], None), ip(RIP));
        let long = format!("rt/{}", "x".repeat(10 * MAX_TEXT_CHARS));
        let f = t.ep(&ep(P2, EndpointKind::Writer, &long), ip(XIP));
        assert_eq!(f.len(), 1);
        assert!(f[0].0.detail.len() < 2 * MAX_TEXT_CHARS + 400);
    }

    #[test]
    fn spdp_from_outside_binding_is_rejected_not_learned() {
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P1, &[], None), ip(RIP));
        t.spdp(&spdp(P2, &[], None), ip(RIP));
        // A profiled prefix claimed by a second host: Critical, contested.
        let f = t.spdp(&spdp(P1, &[XIP], None), ip(XIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
        assert!(f[0].0.detail.contains("contested"), "{f:#?}");
        // An unprofiled one keeps first-come (reported, not learned).
        let f = t.spdp(&spdp(P2, &[XIP], None), ip(XIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Medium);
        assert_eq!(t.b.allows(&P1, ip(XIP)), Some(false));
        assert_eq!(t.b.allows(&P2, ip(XIP)), Some(false));
        assert_eq!(t.b.allows(&P2, ip(RIP)), Some(true));
        assert!(!t.b.is_contested(&P2));
        assert_eq!(t.b.stats().spdp_mismatches, 2);
        // The rejected SPDP's locators were not learned either.
        assert!(!t.ep(&writer(P1), ip(XIP)).is_empty());
    }

    /// Finding 2b: whoever announced a profiled prefix first, once a second
    /// host claims it neither is trusted, for endpoints and samples alike,
    /// until the operator pins it.
    #[test]
    fn contested_profiled_prefix_trusts_no_source() {
        for rogue_first in [true, false] {
            let mut t = T::new(BindingOptions::default());
            let (first, second) = if rogue_first { (XIP, RIP) } else { (RIP, XIP) };
            assert!(t.spdp(&spdp(P1, &[first], None), ip(first)).is_empty());
            assert_eq!(t.b.allows(&P1, ip(first)), Some(true));
            let f = t.spdp(&spdp(P1, &[second], None), ip(second));
            one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
            assert!(t.b.is_contested(&P1));
            assert_eq!(t.b.contested().count(), 1);
            assert_eq!(t.b.stats().contested, 1);
            // Both hosts are untrusted now, the first-bound one included.
            for a in [RIP, XIP] {
                assert_eq!(t.b.allows(&P1, ip(a)), Some(false), "{a:?}");
                let f = t.ep(&writer(P1), ip(a));
                one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
                assert!(f[0].0.detail.contains("contested"), "{f:#?}");
                // Even a non-motion reader announcement is Critical.
                let f = t.ep(&ep(P1, EndpointKind::Reader, "rt/odom"), ip(a));
                one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
                // Further SPDP from either host refreshes nothing.
                let f = t.spdp(&spdp(P1, &[a], None), ip(a));
                one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
            }
            assert!(t.b.profiled_ips(t.now).is_empty());
            // Expiry, dispose and re-announcement do not clear it.
            t.advance(MAX_LEASE * 2);
            let f = t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
            one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
            assert_eq!(
                t.b.observe_participant_removal(&removal(P1, P1), Some(ip(RIP)), Ingress::Unknown),
                Some(false)
            );
            assert!(t.b.is_contested(&P1));
            // Held announcements resolve to a contested mismatch too.
            assert_eq!(t.b.allows(&P1, lo4()), Some(false));
        }
    }

    #[test]
    fn contested_prefix_is_resolved_only_by_a_pin() {
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P1, &[], None), ip(XIP));
        t.spdp(&spdp(P1, &[], None), ip(RIP));
        assert!(t.b.is_contested(&P1));
        // The operator pins it (config reload = a new table with pins); the
        // pin is authoritative over a contest recorded in the same table too.
        let mut pins = BTreeMap::new();
        pins.insert(P1, vec![ip(RIP)]);
        t.b.opts.participant_ips = pins;
        assert!(!t.b.is_contested(&P1));
        assert_eq!(t.b.contested().count(), 0);
        assert_eq!(t.b.allows(&P1, ip(RIP)), Some(true));
        assert_eq!(t.b.allows(&P1, ip(XIP)), Some(false));
        assert!(t.ep(&writer(P1), ip(RIP)).is_empty());
        assert_eq!(t.b.profiled_ips(t.now), [ip(RIP)].into_iter().collect());
    }

    #[test]
    fn multi_homed_refresh_does_not_contest() {
        // A second interface advertised as a locator is the same host.
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P1, &[RIP, RLOC], None), ip(RIP));
        assert!(t.spdp(&spdp(P1, &[RIP, RLOC], None), ip(RLOC)).is_empty());
        assert!(!t.b.is_contested(&P1));
        assert_eq!(
            t.b.profiled_ips(t.now),
            [ip(RIP), ip(RLOC)].into_iter().collect()
        );
        // An unprofiled prefix is never in profiled_ips.
        t.spdp(&spdp(P2, &[], None), ip(XIP));
        assert!(!t.b.profiled_ips(t.now).contains(&ip(XIP)));
        // Expired entries drop out.
        t.advance(MAX_LEASE * 2);
        assert!(t.b.profiled_ips(t.now).is_empty());
    }

    #[test]
    fn refresh_replaces_locators_and_caps_bound_ips() {
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P2, &[[10, 0, 0, 1]], None), ip([10, 0, 0, 1]));
        // Each refresh comes from the previous locator and advertises the next
        // address: a multi-homed / renumbered host walks its binding along.
        for i in 1..=(MAX_BOUND_IPS as u8 + 2) {
            let f = t.spdp(&spdp(P2, &[[10, 0, 0, i + 1]], None), ip([10, 0, 0, i]));
            assert!(f.is_empty(), "{f:#?}");
        }
        assert_eq!(t.b.stats().refreshed, u64::from(MAX_BOUND_IPS as u8 + 2));
        // The oldest bound IP was dropped, the latest locator is allowed, and
        // a locator that was replaced is no longer.
        assert_eq!(t.b.allows(&P2, ip([10, 0, 0, 1])), Some(false));
        assert_eq!(
            t.b.allows(&P2, ip([10, 0, 0, MAX_BOUND_IPS as u8 + 3])),
            Some(true)
        );
    }

    #[test]
    fn lease_expiry_allows_rebind_with_clamped_lease() {
        let mut t = T::new(BindingOptions::default());
        // 1 s lease is clamped to MIN_LEASE.
        t.spdp(&spdp(P2, &[], Some(1)), ip(RIP));
        t.advance(MIN_LEASE / 2);
        assert!(!t.spdp(&spdp(P2, &[], None), ip(XIP)).is_empty());
        t.advance(MIN_LEASE);
        assert!(t.spdp(&spdp(P2, &[], None), ip(XIP)).is_empty());
        assert_eq!(t.b.stats().rebound, 1);
        assert_eq!(t.b.allows(&P2, ip(RIP)), Some(false));
        assert_eq!(t.b.allows(&P2, ip(XIP)), Some(true));
        // A huge / infinite lease is clamped to MAX_LEASE.
        t.spdp(&spdp(P1, &[], Some(i32::MAX)), ip(RIP));
        t.advance(MAX_LEASE + Duration::from_secs(1));
        assert!(t.spdp(&spdp(P1, &[], None), ip(XIP)).is_empty());
        // Negative lease -> default.
        t.spdp(&spdp([0x33; 12], &[], Some(-5)), ip(RIP));
        t.advance(DEFAULT_LEASE / 2);
        assert!(!t.spdp(&spdp([0x33; 12], &[], None), ip(XIP)).is_empty());
    }

    #[test]
    fn pinned_participants_are_authoritative() {
        let mut pins = BTreeMap::new();
        pins.insert(P1, vec![Ipv4Addr::from(RIP).to_ipv6_mapped().into()]);
        let mut t = T::new(BindingOptions {
            participant_ips: pins,
            ..Default::default()
        });
        assert!(t.b.is_bound(&P1));
        assert!(t.b.is_empty(), "pins are not learned entries");
        assert_eq!(t.b.allows(&P1, ip(RIP)), Some(true));
        // Never held: judged at once.
        assert!(t.ep(&writer(P1), ip(RIP)).is_empty());
        let f = t.ep(&writer(P1), ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert!(f[0].0.detail.contains("pinned"));
        assert_eq!(t.b.held_len(), 0);
        // SPDP from outside the pins is rejected, never learned over.
        let f = t.spdp(&spdp(P1, &[XIP], None), ip(XIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::High);
        assert!(t.spdp(&spdp(P1, &[], None), ip(RIP)).is_empty());
        assert_eq!(t.b.allows(&P1, ip(XIP)), Some(false));
        assert_eq!(t.b.options().participant_ips[&P1], vec![ip(RIP)]);
    }

    #[test]
    fn relays_and_guid_conflicts_need_a_discovery_server() {
        let mut t = T::new(BindingOptions {
            discovery_servers: vec![Ipv4Addr::from(DS).to_ipv6_mapped().into()],
            ..Default::default()
        });
        let mut relayed = writer(P1);
        relayed.source = P2;
        assert!(t.ep(&relayed, ip(DS)).is_empty(), "trusted relay");
        let f = t.ep(&relayed, ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert!(f[0].0.detail.contains("relayed"));
        let mut conflict = writer(P1);
        conflict.guid_conflict = true;
        assert!(t.ep(&conflict, ip(DS)).is_empty());
        let f = t.ep(&conflict, ip(XIP));
        assert!(f[0].0.detail.contains("PID_PARTICIPANT_GUID"));
        // Relayed SPDP: untrusted rejected; trusted teaches locators only.
        let mut s = spdp(P2, &[RLOC], None);
        s.source = P1;
        one(
            &t.spdp(&s, ip(XIP)),
            rules::PARTICIPANT_SOURCE_MISMATCH,
            Severity::Medium,
        );
        assert!(!t.b.is_bound(&P2));
        assert!(t.spdp(&s, ip(DS)).is_empty());
        assert_eq!(t.b.allows(&P2, ip(RLOC)), Some(true));
        assert_eq!(t.b.allows(&P2, ip(DS)), Some(false), "server IP not bound");
        // A second relayed SPDP refreshes (replaces) the locators.
        let mut s2 = spdp(P2, &[RIP], None);
        s2.source = P1;
        assert!(t.spdp(&s2, ip(DS)).is_empty());
        assert_eq!(t.b.allows(&P2, ip(RLOC)), Some(false));
        assert_eq!(t.b.allows(&P2, ip(RIP)), Some(true));
    }

    #[test]
    fn relay_trust_is_by_source_ip_never_by_sender_prefix() {
        // A real server at DS relays P1's writer under its own prefix P2.
        let mut t = T::new(BindingOptions {
            discovery_servers: vec![ip(DS)],
            ..Default::default()
        });
        let mut relayed = writer(P1);
        relayed.source = P2;
        assert!(t.ep(&relayed, ip(DS)).is_empty(), "trusted relay");
        // Another host copies the server's sender prefix: still a mismatch,
        // the prefix it saw the server use buys it nothing.
        let f = t.ep(&relayed, ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        // Its SPDP relayed under the server's prefix teaches nothing either.
        let p3: GuidPrefix = [0x33; 12];
        let mut s = spdp(p3, &[XIP], None);
        s.source = P2;
        assert!(!t.spdp(&s, ip(XIP)).is_empty());
        assert!(!t.b.is_bound(&p3));
        assert_eq!(t.b.allows(&p3, ip(XIP)), None);
    }

    // ---- hold queue ------------------------------------------------------

    #[test]
    fn held_endpoints_are_judged_when_spdp_arrives() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.ep(&writer(P1), ip(RIP)).is_empty());
        assert!(t.ep(&writer(P1), ip(XIP)).is_empty());
        assert!(t.ep(&writer(P1), ip(XIP)).is_empty(), "repeat not re-held");
        assert_eq!(t.b.held_len(), 2);
        assert_eq!(t.b.stats().held, 2);
        let f = t.spdp(&spdp(P1, &[], None), ip(RIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert_eq!(f[0].1, "192.168.50.66");
        assert_eq!(t.b.held_len(), 0);
        assert_eq!(t.b.stats().held_resolved, 2);
    }

    #[test]
    fn held_endpoints_expire_as_unannounced() {
        let mut t = T::new(BindingOptions::default());
        t.ep(&writer(P1), ip(XIP));
        t.ep(&ep(P2, EndpointKind::Reader, "rt/odom"), ip(XIP));
        t.advance(DEFAULT_HOLD - Duration::from_secs(1));
        assert!(t.expire().is_empty());
        t.advance(Duration::from_secs(2));
        let f = t.expire();
        assert_eq!(f.len(), 2, "{f:#?}");
        assert_eq!(f[0].0.rule, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT);
        assert_eq!(f[0].0.severity, Severity::High, "motion writer");
        assert_eq!(f[1].0.severity, Severity::Medium);
        assert_eq!(t.b.stats().held_expired, 2);
        assert_eq!(t.b.held_len(), 0);
        // A late SPDP finds nothing held.
        assert!(t.spdp(&spdp(P1, &[], None), ip(RIP)).is_empty());
    }

    #[test]
    fn zero_hold_reports_at_once_and_flush_reports_the_rest() {
        let mut t = T::new(BindingOptions {
            hold: Duration::ZERO,
            ..Default::default()
        });
        one(
            &t.ep(&writer(P1), ip(XIP)),
            rules::ENDPOINT_UNANNOUNCED_PARTICIPANT,
            Severity::High,
        );
        assert_eq!(t.b.held_len(), 0);
        let mut t = T::new(BindingOptions::default());
        t.ep(&writer(P2), ip(XIP));
        let mut out = Vec::new();
        t.b.flush(&t.prof, &mut out);
        one(
            &out,
            rules::ENDPOINT_UNANNOUNCED_PARTICIPANT,
            Severity::High,
        );
        assert!(out[0].0.detail.contains("end of the input"));
    }

    #[test]
    fn held_queue_overflow_reports_the_oldest() {
        let mut t = T::new(BindingOptions {
            max_pending: 2,
            ..Default::default()
        });
        t.ep(&writer([1; 12]), ip(XIP));
        t.ep(&writer([2; 12]), ip(XIP));
        let f = t.ep(&writer([3; 12]), ip(XIP));
        one(&f, rules::ENDPOINT_UNANNOUNCED_PARTICIPANT, Severity::High);
        assert!(f[0].0.detail.contains(&hex12(&[1; 12])));
        assert!(f[0].0.detail.contains("overflowed"));
        assert_eq!(t.b.held_len(), 2);
        assert_eq!(t.b.stats().held_overflow, 1);
        // The evicted participant's SPDP no longer finds anything held, the
        // others still resolve.
        assert!(t.spdp(&spdp([1; 12], &[], None), ip(RIP)).is_empty());
        let f = t.spdp(&spdp([3; 12], &[], None), ip(RIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert_eq!(t.b.held_len(), 1);
    }

    #[test]
    fn options_are_clamped() {
        let t = T::new(BindingOptions {
            hold: Duration::from_secs(1_000_000),
            max_participants: 0,
            max_pending: usize::MAX,
            ..Default::default()
        });
        assert_eq!(t.b.options().hold, MAX_HOLD);
        assert_eq!(t.b.options().max_participants, 1);
        assert_eq!(t.b.options().max_pending, DEFAULT_MAX_PENDING);
    }

    // ---- eviction ----------------------------------------------------------

    #[test]
    fn eviction_spares_profiled_participants() {
        let mut t = T::new(BindingOptions {
            max_participants: 2,
            ..Default::default()
        });
        t.spdp(&spdp(P1, &[], None), ip(RIP));
        for i in 0..50u8 {
            t.advance(Duration::from_millis(1));
            let mut q = [0xee; 12];
            q[0] = i;
            t.spdp(&spdp(q, &[], None), ip([10, 1, 0, i]));
        }
        assert_eq!(t.b.len(), 2);
        assert!(t.b.is_bound(&P1), "profiled entry survives the spray");
        assert_eq!(t.b.stats().evicted, 49);
        // When every entry is profiled, the oldest profiled one goes.
        let mut t = T::new(BindingOptions {
            max_participants: 1,
            ..Default::default()
        });
        t.spdp(&spdp(P1, &[], None), ip(RIP));
        t.spdp(&spdp(P2, &[], None), ip(RIP));
        assert!(!t.b.is_bound(&P1));
        assert!(t.b.is_bound(&P2));
    }

    // ---- removals, disabled, unparsed --------------------------------------

    #[test]
    fn participant_removal_is_judged_against_the_binding() {
        let mut t = T::new(BindingOptions {
            discovery_servers: vec![ip(DS)],
            ..Default::default()
        });
        t.spdp(&spdp(P1, &[], None), ip(RIP));
        assert_eq!(
            t.b.observe_participant_removal(&removal(P2, P2), Some(ip(RIP)), Ingress::Unknown),
            None
        );
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), None, Ingress::Unknown),
            None
        );
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), Some(ip(XIP)), Ingress::Unknown),
            Some(false)
        );
        assert!(t.b.is_bound(&P1));
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), Some(ip(RIP)), Ingress::Unknown),
            Some(true)
        );
        assert!(!t.b.is_bound(&P1));
        assert_eq!(t.b.stats().removed, 1);
        // Relayed by a trusted server.
        t.spdp(&spdp(P2, &[], None), ip(RIP));
        assert_eq!(
            t.b.observe_participant_removal(&removal(P2, P1), Some(ip(DS)), Ingress::Unknown),
            Some(true)
        );
        assert!(!t.b.is_bound(&P2));
    }

    #[test]
    fn disabled_table_does_nothing_and_bad_src_ip_is_counted() {
        let mut t = T::new(BindingOptions {
            enabled: false,
            ..Default::default()
        });
        assert!(t.spdp(&spdp(P1, &[], None), ip(RIP)).is_empty());
        assert!(t.ep(&writer(P1), ip(XIP)).is_empty());
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), Some(ip(XIP)), Ingress::Unknown),
            None
        );
        assert!(t.b.is_empty());
        let mut t = T::new(BindingOptions::default());
        let mut out = Vec::new();
        t.b.observe_spdp(
            &t.prof,
            &spdp(P1, &[], None),
            None,
            Ingress::Unknown,
            t.now,
            &mut out,
        );
        t.b.observe_endpoint(
            &t.prof,
            &writer(P1),
            None,
            Ingress::Unknown,
            false,
            t.now,
            &mut out,
        );
        assert!(out.is_empty());
        assert_eq!(t.b.stats().unparsed_src_ip, 2);
    }

    // ---- same-host traffic over loopback ------------------------------------

    /// R3-P4 at the unit level: the legit writer's SEDP over `lo`.
    #[test]
    fn same_host_sedp_over_loopback_is_accepted() {
        for ing in [Ingress::Loopback, Ingress::Unknown] {
            let mut t = T::local();
            t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
            assert!(t.ep_in(&writer(P1), lo4(), ing).is_empty(), "{ing:?}");
            assert!(t
                .ep_in(&writer(P1), IpAddr::V6(Ipv6Addr::LOCALHOST), ing)
                .is_empty());
            assert_eq!(t.b.allows_from(&P1, lo4(), ing), Some(true));
            assert_eq!(t.b.stats().same_host_loopback, 2);
            assert_eq!(t.b.stats().endpoint_mismatches, 0);
        }
    }

    #[test]
    fn loopback_from_a_non_loopback_interface_is_forged_and_critical() {
        let mut t = T::local();
        t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
        // Even a reader on a non-motion topic: forged source = Critical.
        let f = t.ep_in(
            &ep(P1, EndpointKind::Reader, "rt/odom"),
            lo4(),
            Ingress::External,
        );
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert!(f[0].0.detail.contains("forged"));
        // Unbound participant: not held, judged at once.
        let f = t.ep_in(&writer(P2), lo4(), Ingress::External);
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert_eq!(t.b.held_len(), 0);
        // SPDP: rejected (Critical), not learned, even for a fresh prefix.
        let f = t.spdp_in(&spdp(P2, &[], None), lo4(), Ingress::External);
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
        assert!(!t.b.is_bound(&P2));
        // Removal: not accepted, binding kept.
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), Some(lo4()), Ingress::External),
            Some(false)
        );
        assert!(t.b.is_bound(&P1));
        assert_eq!(t.b.allows_from(&P1, lo4(), Ingress::External), Some(false));
        assert_eq!(t.b.allows_from(&P2, lo4(), Ingress::External), None);
        assert_eq!(t.b.stats().spoofed_loopback, 4);
        // A non-loopback source on an external interface is judged normally.
        assert!(t.ep_in(&writer(P1), ip(RIP), Ingress::External).is_empty());
    }

    #[test]
    fn remote_participant_over_loopback_is_still_a_mismatch() {
        let mut t = T::local();
        t.spdp(&spdp(P1, &[XIP], None), ip(XIP));
        let f = t.ep_in(&writer(P1), lo4(), Ingress::Loopback);
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        // Without local_addresses even the robot's own participant is not
        // known to be same-host.
        let mut t = T::new(BindingOptions::default());
        t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
        assert_eq!(t.ep_in(&writer(P1), lo4(), Ingress::Loopback).len(), 1);
    }

    #[test]
    fn strict_mode_judges_unknown_ingress_loopback_normally() {
        let mut t = T::new(BindingOptions {
            local_addresses: vec![ip(RIP)],
            strict_loopback_ingress: true,
            ..Default::default()
        });
        t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
        assert_eq!(t.ep_in(&writer(P1), lo4(), Ingress::Unknown).len(), 1);
        assert!(t.ep_in(&writer(P1), lo4(), Ingress::Loopback).is_empty());
    }

    #[test]
    fn localhost_only_participants_are_same_host() {
        // ROS_LOCALHOST_ONLY: SPDP itself comes from 127.0.0.1.
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P1, &[], None), lo4()).is_empty());
        assert!(t
            .ep_in(
                &writer(P1),
                IpAddr::from([127, 0, 0, 53]),
                Ingress::Loopback
            )
            .is_empty());
        assert!(t.ep(&writer(P1), lo4()).is_empty());
        assert_eq!(t.ep(&writer(P1), ip(XIP)).len(), 1);
    }

    #[test]
    fn local_addresses_are_learned_from_the_loopback_interface() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.b.local_addresses().is_empty());
        // Only the host can send on lo: its source IP is a local address.
        t.spdp_in(&spdp(P2, &[], None), ip(RIP), Ingress::Loopback);
        assert_eq!(t.b.local_addresses(), &[ip(RIP)]);
        assert!(t.b.is_local(ip(RIP)) && t.b.is_local(lo4()) && !t.b.is_local(ip(XIP)));
        // Not from other interfaces, not loopback itself, no duplicates.
        t.ep_in(&writer(P2), ip(XIP), Ingress::External);
        t.ep_in(&writer(P2), ip(XIP), Ingress::Unknown);
        t.ep_in(&writer(P2), lo4(), Ingress::Loopback);
        t.ep_in(&writer(P2), ip(RIP), Ingress::Loopback);
        assert_eq!(t.b.local_addresses(), &[ip(RIP)]);
        assert_eq!(t.b.stats().local_learned, 1);
        // P1 bound (on the wire) to the learned address is same-host.
        t.spdp_in(&spdp(P1, &[], None), ip(RIP), Ingress::External);
        assert!(t.ep_in(&writer(P1), lo4(), Ingress::Loopback).is_empty());
    }

    #[test]
    fn local_address_list_is_canonical_bounded_and_detectable() {
        let mut list: Vec<IpAddr> = vec![
            Ipv4Addr::from(RIP).to_ipv6_mapped().into(),
            ip(RIP),
            IpAddr::from([0, 0, 0, 0]),
            IpAddr::from([239, 0, 0, 1]),
        ];
        list.extend((0..100u8).map(|i| ip([10, 2, 0, i])));
        let t = T::new(BindingOptions {
            local_addresses: list,
            detect_local_addresses: true,
            ..Default::default()
        });
        assert_eq!(t.b.local_addresses()[0], ip(RIP));
        assert_eq!(t.b.local_addresses().len(), MAX_LOCAL_ADDRESSES);
        assert!(t.b.local_addresses()[1..].iter().all(|a| *a != ip(RIP)));
    }

    #[test]
    fn same_host_pins_and_relays_over_loopback() {
        let mut pins = BTreeMap::new();
        pins.insert(P1, vec![ip(RIP)]);
        let mut t = T::new(BindingOptions {
            participant_ips: pins.clone(),
            local_addresses: vec![ip(RIP)],
            discovery_servers: vec![ip(RIP)],
            ..Default::default()
        });
        assert!(t.ep_in(&writer(P1), lo4(), Ingress::Loopback).is_empty());
        assert!(t
            .spdp_in(&spdp(P1, &[], None), lo4(), Ingress::Loopback)
            .is_empty());
        // A discovery server on this host relays over loopback.
        let mut relayed = writer(P2);
        relayed.source = P1;
        assert!(t.ep_in(&relayed, lo4(), Ingress::Loopback).is_empty());
        assert_eq!(t.ep_in(&relayed, lo4(), Ingress::External).len(), 1);
        // Pinned to a remote IP: loopback is not it.
        let mut t = T::new(BindingOptions {
            participant_ips: pins,
            ..Default::default()
        });
        let f = t.ep_in(&writer(P1), lo4(), Ingress::Loopback);
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
        assert!(f[0].0.detail.contains("pinned"));
    }

    #[test]
    fn spdp_refresh_over_loopback_for_a_same_host_participant() {
        let mut t = T::local();
        t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
        assert!(t
            .spdp_in(&spdp(P1, &[RIP], None), lo4(), Ingress::Loopback)
            .is_empty());
        assert_eq!(t.b.stats().refreshed, 1);
        assert_eq!(t.b.stats().spdp_mismatches, 0);
        // A remote participant's SPDP over loopback is still rejected.
        t.spdp(&spdp(P2, &[XIP], None), ip(XIP));
        let f = t.spdp_in(&spdp(P2, &[XIP], None), lo4(), Ingress::Loopback);
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Medium);
    }

    #[test]
    fn held_loopback_announcements_keep_their_ingress() {
        let mut t = T::local();
        // SEDP over lo before the SPDP: held, then accepted.
        assert!(t.ep_in(&writer(P1), lo4(), Ingress::Loopback).is_empty());
        assert_eq!(t.b.held_len(), 1);
        assert!(t.spdp(&spdp(P1, &[RIP], None), ip(RIP)).is_empty());
        assert_eq!(t.b.held_len(), 0);
        // Same for a remote participant: the held lo announcement is a
        // mismatch once the SPDP shows it is not on this host.
        assert!(t.ep_in(&writer(P2), lo4(), Ingress::Loopback).is_empty());
        let f = t.spdp(&spdp(P2, &[XIP], None), ip(XIP));
        one(&f, rules::ENDPOINT_SOURCE_MISMATCH, Severity::Critical);
    }

    // ---- quarantine locators (red team F3) ------------------------------

    #[test]
    fn quarantine_locators_outlive_the_binding_and_stay_the_prefixs_own() {
        const P3: GuidPrefix = [0x33; 12];
        const P3IP: [u8; 4] = [192, 168, 50, 67];
        let mut t = T::new(BindingOptions::default());
        let at = |a: [u8; 4]| SocketAddr::new(ip(a), 7410);
        assert!(t.spdp(&spdp(P2, &[XIP], Some(10)), ip(XIP)).is_empty());
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![at(XIP)]);
        // A conflicting SPDP for the live prefix from another host is
        // rejected and changes nothing.
        let f = t.spdp(&spdp(P2, &[DS], Some(10)), ip(DS));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![at(XIP)]);
        // It disposes itself: the binding is gone, its locators are kept.
        assert_eq!(
            t.b.observe_participant_removal(&removal(P2, P2), Some(ip(XIP)), Ingress::Unknown),
            Some(true)
        );
        assert!(!t.b.is_bound(&P2));
        assert!(t.b.spdp_unicast(&P2, t.now).is_empty());
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![at(XIP)]);
        // ...for the retention period only.
        let late = t.now + LOCATOR_RETENTION + Duration::from_secs(1);
        assert!(t.b.quarantine_locators(&P2, late).is_empty());
        // Never seen: nothing.
        assert!(t.b.quarantine_locators(&P3, t.now).is_empty());

        // P3 copies the robot's (profiled P1) locator next to its own: it
        // never gets the robot's, live or after the robot's lease ran out.
        assert!(t.spdp(&spdp(P1, &[RIP], Some(10)), ip(RIP)).is_empty());
        assert!(t
            .spdp(&spdp(P3, &[RIP, P3IP], Some(10)), ip(P3IP))
            .is_empty());
        assert_eq!(t.b.quarantine_locators(&P3, t.now), vec![at(P3IP)]);
        t.advance(Duration::from_secs(60));
        assert!(t.b.spdp_unicast(&P1, t.now).is_empty(), "P1 expired");
        assert_eq!(t.b.quarantine_locators(&P3, t.now), vec![at(P3IP)]);
        // P3 left and P1 is back: P1 keeps its own locator.
        assert_eq!(t.b.quarantine_locators(&P1, t.now), vec![at(RIP)]);
    }

    #[test]
    fn a_contested_or_pinned_prefix_gets_no_quarantine_locators() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P1, &[RIP], None), ip(RIP)).is_empty());
        assert!(!t.b.quarantine_locators(&P1, t.now).is_empty());
        // A second host claims the profiled prefix: contested, nothing
        // (neither live nor remembered), so a quarantine never cuts the
        // legitimate owner.
        let f = t.spdp(&spdp(P1, &[XIP], None), ip(XIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
        assert!(t.b.is_contested(&P1));
        assert!(t.b.quarantine_locators(&P1, t.now).is_empty());
        t.advance(Duration::from_secs(3600));
        assert!(t.b.quarantine_locators(&P1, t.now).is_empty());

        // A pinned prefix learns no locators; its pinned address is never
        // handed out for another prefix either.
        let mut pins = BTreeMap::new();
        pins.insert(P1, vec![ip(RIP)]);
        let mut t = T::new(BindingOptions {
            participant_ips: pins,
            ..Default::default()
        });
        assert!(t.spdp(&spdp(P1, &[RIP], None), ip(RIP)).is_empty());
        assert!(t.b.quarantine_locators(&P1, t.now).is_empty());
        assert!(t.spdp(&spdp(P2, &[RIP, XIP], None), ip(XIP)).is_empty());
        assert_eq!(
            t.b.quarantine_locators(&P2, t.now),
            vec![SocketAddr::new(ip(XIP), 7410)]
        );
    }

    #[test]
    fn spdp_only_prefixes_are_forgotten_before_active_ones() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P2, &[XIP], None), ip(XIP)).is_empty());
        assert!(t.ep(&writer(P2), ip(XIP)).len() <= 1);
        for i in 0..(MAX_LOCATOR_HISTORY as u32 + 10) {
            let mut g = [0x44; 12];
            g[..4].copy_from_slice(&i.to_be_bytes());
            t.advance(Duration::from_millis(1));
            t.spdp(&spdp(g, &[DS], None), ip(DS));
        }
        assert!(t.b.stats().locators_forgotten >= 10);
        assert!(t.b.history.len() <= MAX_LOCATOR_HISTORY);
        assert_eq!(
            t.b.quarantine_locators(&P2, t.now),
            vec![SocketAddr::new(ip(XIP), 7410)]
        );
    }

    // ---- review of the F3 fix (H1, H2, M5, M6, M7) ----------------------

    const P3: GuidPrefix = [0x33; 12];

    fn sa(a: [u8; 4]) -> SocketAddr {
        SocketAddr::new(ip(a), 7410)
    }

    #[test]
    fn a_profiled_participant_back_from_its_own_addresses_is_not_contested() {
        let mut t = T::new(BindingOptions::default());
        assert!(t
            .spdp(&spdp(P1, &[RIP, RLOC], Some(10)), ip(RIP))
            .is_empty());
        t.advance(Duration::from_secs(60));
        // Back from its bound address, then (lease run out again) from its
        // second interface, an announced locator address.
        assert!(t
            .spdp(&spdp(P1, &[RIP, RLOC], Some(10)), ip(RIP))
            .is_empty());
        t.advance(Duration::from_secs(60));
        assert!(t
            .spdp(&spdp(P1, &[RIP, RLOC], Some(10)), ip(RLOC))
            .is_empty());
        // It disposes itself and comes back.
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), Some(ip(RLOC)), Ingress::Unknown),
            Some(true)
        );
        assert!(t
            .spdp(&spdp(P1, &[RIP, RLOC], Some(10)), ip(RIP))
            .is_empty());
        assert!(!t.b.is_contested(&P1));
        assert_eq!(t.b.stats().foreign_rebinds, 0);
        assert_eq!(t.b.quarantine_locators(&P1, t.now), vec![sa(RIP), sa(RLOC)]);
        assert_eq!(t.b.locator_rank(&P1), Some(Rank::Profiled));
        // After a dispose, a foreign host is caught too.
        assert_eq!(
            t.b.observe_participant_removal(&removal(P1, P1), Some(ip(RIP)), Ingress::Unknown),
            Some(true)
        );
        let f = t.spdp(&spdp(P1, &[XIP], Some(10)), ip(XIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
        assert_eq!(f[0].2, Some(P1), "structured participant");
        assert!(t.b.is_contested(&P1));
        assert_eq!(t.b.stats().foreign_rebinds, 1);
    }

    #[test]
    fn a_relayed_foreign_announcement_of_a_profiled_prefix_contests_it() {
        let mut t = T::new(BindingOptions {
            discovery_servers: vec![ip(DS)],
            ..Default::default()
        });
        assert!(t.spdp(&spdp(P1, &[RIP], Some(10)), ip(RIP)).is_empty());
        t.advance(Duration::from_secs(60));
        let mut relayed = spdp(P1, &[XIP], Some(10));
        relayed.source = P2;
        let f = t.spdp(&relayed, ip(DS));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
        assert!(t.b.is_contested(&P1));
        // The robot's remembered locator is still protected.
        assert!(t.spdp(&spdp(P2, &[XIP, RIP], None), ip(RIP)).is_empty());
        let q = t.b.quarantine_target(&P2, t.now);
        assert!(q.locators.is_empty(), "{q:?}");
        assert_eq!(q.excluded[1], (sa(RIP), excluded::PROFILED), "{q:?}");
    }

    #[test]
    fn quarantine_target_reasons_and_guid_only() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P1, &[RIP], None), ip(RIP)).is_empty());
        let lo = [127, 0, 0, 1];
        let far = [10, 99, 0, 1];
        assert!(t
            .spdp(&spdp(P2, &[XIP, lo, far, RIP], None), ip(XIP))
            .is_empty());
        let q = t.b.quarantine_target(&P2, t.now);
        assert_eq!(q.locators, vec![sa(XIP)]);
        assert!(q.known && q.guid_only);
        assert_eq!(
            q.excluded,
            vec![
                (sa(lo), excluded::LOOPBACK),
                (sa(far), excluded::NOT_OBSERVED),
                (sa(RIP), excluded::NOT_OBSERVED),
            ]
        );
        // The robot's own: its locators, never by GUID prefix alone.
        let q = t.b.quarantine_target(&P1, t.now);
        assert_eq!(q.locators, vec![sa(RIP)]);
        assert!(q.known && !q.guid_only);
        // Spoofed from the robot's address (an announced locator, so the
        // binding accepts it): still never the robot's ip:port...
        assert!(t.spdp(&spdp(P2, &[XIP, RIP], None), ip(RIP)).is_empty());
        let q = t.b.quarantine_target(&P2, t.now);
        assert_eq!(q.locators, vec![sa(XIP)]);
        assert_eq!(q.excluded, vec![(sa(RIP), excluded::PROFILED)]);
        // ...while the robot's own quarantine (a deliberate SOC choice)
        // still gets its ip:port: two prefixes seen at one address share
        // the host (review R2-3).
        let q = t.b.quarantine_target(&P1, t.now);
        assert_eq!(q.locators, vec![sa(RIP)]);
        // Unknown: nothing, and nothing by GUID prefix.
        let q = t.b.quarantine_target(&P3, t.now);
        assert!(!q.known && !q.guid_only && q.locators.is_empty());
    }

    /// Review R2-3 (a): a second prefix seen at the rogue's own address
    /// (its self-decoy, no spoofing needed) announcing the same ip:port
    /// shares the host: both get it (before, neither did, and the rogue's
    /// quarantine was by GUID prefix only).
    #[test]
    fn a_same_host_decoy_shares_the_locator() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P2, &[XIP], None), ip(XIP)).is_empty());
        // From another address: no evidence, no effect (H2a).
        assert!(t.spdp(&spdp(P3, &[XIP], None), ip(DS)).is_empty());
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![sa(XIP)]);
        assert!(t.b.quarantine_locators(&P3, t.now).is_empty());
        // From the rogue's own address: the same host.
        assert!(t.spdp(&spdp(P3, &[XIP], None), ip(XIP)).is_empty());
        for p in [P2, P3] {
            let q = t.b.quarantine_target(&p, t.now);
            assert_eq!(q.locators, vec![sa(XIP)], "{q:?}");
            assert!(q.excluded.is_empty() && q.guid_only, "{q:?}");
        }
    }

    /// A departed prefix's port is handed out also once a successor on the
    /// same host announces it (review R2-3: the rogue rotating its prefix,
    /// or staggering a self-decoy, is the same host).
    #[test]
    fn a_departed_prefixs_port_stays_its_own_with_a_successor_on_the_host() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P2, &[XIP], Some(10)), ip(XIP)).is_empty());
        t.advance(Duration::from_secs(60));
        assert!(t.spdp(&spdp(P3, &[XIP], Some(10)), ip(XIP)).is_empty());
        assert_eq!(t.b.quarantine_locators(&P3, t.now), vec![sa(XIP)]);
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![sa(XIP)]);
        t.advance(Duration::from_secs(60));
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![sa(XIP)]);
    }

    /// Review R2-5: a non-profiled prefix never gets any port of the
    /// robot's own computer; the robot's own quarantine keeps its exact
    /// ip:ports only. Since review R3-6 "the robot's own computer" is an
    /// address an SPDP cannot claim: this host's, or one pinned to a
    /// profiled participant
    /// (`a_first_come_claim_of_a_profiled_prefix_does_not_shield_the_attackers_host`):
    /// an address a profiled participant was only learned at is never cut
    /// whole (R3-1), but a non-profiled prefix's own locators there are.
    #[test]
    fn a_profiled_hosts_other_ports_are_protected() {
        let decoy = |t: &mut T| {
            assert!(t.spdp(&spdp(P1, &[RIP], None), ip(RIP)).is_empty());
            let mut d = spdp(P2, &[RIP, XIP], None);
            d.metatraffic_unicast[0].port = 7412;
            assert!(t.spdp(&d, ip(RIP)).is_empty());
            t.spdp(&d, ip(XIP));
            t.b.quarantine_target(&P2, t.now)
        };
        // This host: commissioned.
        let mut t = T::local();
        let q = decoy(&mut t);
        assert_eq!(q.locators, vec![sa(XIP)]);
        assert_eq!(
            q.excluded,
            vec![(SocketAddr::new(ip(RIP), 7412), excluded::THIS_HOST)]
        );
        assert_eq!(q.addresses, vec![ip(XIP)]);
        assert_eq!(q.excluded_addresses, vec![(ip(RIP), excluded::THIS_HOST)]);
        // Learned only: the decoy's own port there is cut, the address
        // never whole.
        let mut t = T::new(BindingOptions::default());
        let q = decoy(&mut t);
        assert_eq!(q.locators, vec![SocketAddr::new(ip(RIP), 7412), sa(XIP)]);
        assert_eq!(q.addresses, vec![ip(XIP)]);
        assert_eq!(
            q.excluded_addresses,
            vec![(ip(RIP), excluded::LEARNED_PROFILED_HOST)]
        );
    }

    /// Review R3-6: an attacker that announces a profiled prefix first
    /// (before the real participant appears, or after its remembered
    /// evidence lapsed) is bound first-come, and its address counted as
    /// "the robot's own computer": every port there was left out of a
    /// rogue's quarantine (`PROFILED_HOST`). Only addresses an SPDP cannot
    /// claim (pins, this host's) shield other ports now; a learned one (and
    /// a profile identity's ips) is only never cut **whole** (it may be the
    /// robot's computer), so the rogue's own locators there are cut and the
    /// answer says `partial`.
    #[test]
    fn a_first_come_claim_of_a_profiled_prefix_does_not_shield_the_attackers_host() {
        let mut t = T::new(BindingOptions::default());
        // The attacker announces the robot's prefix first, then a rogue on
        // another port of the same host.
        assert!(t.spdp(&spdp(P1, &[XIP], None), ip(XIP)).is_empty());
        let mut r = spdp(P2, &[XIP], None);
        r.metatraffic_unicast[0].port = 7412;
        assert!(t.spdp(&r, ip(XIP)).is_empty());
        let rogue = SocketAddr::new(ip(XIP), 7412);
        let q = t.b.quarantine_target(&P2, t.now);
        assert_eq!(q.locators, vec![rogue], "{q:?}");
        assert!(q.excluded.is_empty(), "{q:?}");
        assert!(q.addresses.is_empty(), "{q:?}");
        assert_eq!(
            q.excluded_addresses,
            vec![(ip(XIP), excluded::LEARNED_PROFILED_HOST)]
        );
        // The real participant appears: contested (Critical); nothing about
        // the attacker's host changes.
        let f = t.spdp(&spdp(P1, &[RIP], None), ip(RIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::Critical);
        assert!(t.b.is_contested(&P1));
        assert_eq!(t.b.quarantine_target(&P2, t.now).locators, vec![rogue]);

        // Pinned (commissioned): the attacker's claim is never learned, the
        // pinned address is protected, the attacker's is cut whole.
        let mut t = T::new(BindingOptions {
            participant_ips: [(P1, vec![ip(RIP)])].into_iter().collect(),
            ..Default::default()
        });
        let f = t.spdp(&spdp(P1, &[XIP], None), ip(XIP));
        one(&f, rules::PARTICIPANT_SOURCE_MISMATCH, Severity::High);
        let mut d = spdp(P2, &[XIP, RIP], None);
        d.metatraffic_unicast[1].port = 7412;
        assert!(t.spdp(&d, ip(XIP)).is_empty());
        t.spdp(&d, ip(RIP));
        let q = t.b.quarantine_target(&P2, t.now);
        assert_eq!(q.locators, vec![sa(XIP)], "{q:?}");
        assert_eq!(
            q.excluded,
            vec![(SocketAddr::new(ip(RIP), 7412), excluded::PINNED_ELSEWHERE)]
        );
        assert_eq!(q.addresses, vec![ip(XIP)], "{q:?}");
        assert_eq!(
            q.excluded_addresses,
            vec![(ip(RIP), excluded::PINNED_ELSEWHERE)]
        );

        // A profile identity's ips are never cut whole (its own locators
        // there may be: a rogue matching the identity, red team F3).
        let mut prof = profile();
        prof.participant_identities.insert(
            "robot".into(),
            robodr_events::profile::ParticipantIdentity {
                ips: [RIP].iter().map(|a| ip(*a).to_string()).collect(),
                vendor: "010f".into(),
                enclave: None,
                nodes: Default::default(),
                max_instances: 1,
            },
        );
        let mut b = BindingTable::new(BindingOptions::default(), &prof);
        let mut out = Vec::new();
        b.observe_spdp(&prof, &d, Some(ip(RIP)), Ingress::Unknown, t.now, &mut out);
        b.observe_spdp(&prof, &d, Some(ip(XIP)), Ingress::Unknown, t.now, &mut out);
        let q = b.quarantine_target(&P2, t.now);
        assert_eq!(
            q.locators,
            vec![sa(XIP), SocketAddr::new(ip(RIP), 7412)],
            "{q:?}"
        );
        assert_eq!(q.addresses, vec![ip(XIP)], "{q:?}");
        assert_eq!(
            q.excluded_addresses,
            vec![(ip(RIP), excluded::IDENTITY_HOST)]
        );
    }

    /// Review R2-3 (c): a prefix ranked High or above that comes back
    /// from a new address after its lease keeps its evidence and rank
    /// (merged); a lower-ranked one is a new owner (replaced).
    #[test]
    fn a_reannounce_merges_the_evidence_of_a_high_ranked_prefix() {
        let mut t = T::new(BindingOptions::default());
        let other = [192, 168, 50, 67];
        assert!(t.spdp(&spdp(P2, &[XIP], Some(10)), ip(XIP)).is_empty());
        assert!(t.spdp(&spdp(P3, &[DS], Some(10)), ip(DS)).is_empty());
        t.b.note_soc_reference(&P2);
        t.b.note_finding(&P2, Severity::Critical);
        t.advance(Duration::from_secs(60));
        assert!(t.spdp(&spdp(P2, &[other], Some(10)), ip(other)).is_empty());
        assert!(t.spdp(&spdp(P3, &[other], Some(10)), ip(other)).is_empty());
        assert_eq!(t.b.locator_rank(&P2), Some(Rank::SocReferenced));
        assert_eq!(
            t.b.quarantine_locators(&P2, t.now),
            vec![sa(other), sa(XIP)]
        );
        assert_eq!(t.b.locator_rank(&P3), Some(Rank::SpdpOnly));
        assert_eq!(t.b.quarantine_locators(&P3, t.now), vec![sa(other)]);
        assert_eq!(t.b.stats().evidence_merged, 1);
    }

    /// Review R2-4: under global pressure the fullest per-source bucket
    /// is evicted first; a SOC-named prefix is never evicted for others.
    #[test]
    fn global_eviction_takes_the_fullest_bucket_first() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P2, &[XIP], None), ip(XIP)).is_empty());
        t.b.note_finding(&P2, Severity::Critical);
        for i in 0..(MAX_LOCATOR_HISTORY as u32 + 100) {
            let src = [10, 0, 1, (i % 10) as u8 + 1];
            let mut g = [0x44; 12];
            g[..4].copy_from_slice(&i.to_be_bytes());
            t.advance(Duration::from_millis(1));
            t.spdp(&spdp(g, &[src], None), ip(src));
            t.b.note_finding(&g, Severity::Critical);
        }
        assert_eq!(t.b.history.len(), MAX_LOCATOR_HISTORY);
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![sa(XIP)]);
        // One address per sprayed prefix (spoofed): the lone rogue is the
        // oldest of the fullest buckets now, unless the SOC named it.
        t.b.note_soc_reference(&P2);
        for i in 0..(2 * MAX_LOCATOR_HISTORY as u32) {
            let src = [10, 1, (i >> 8) as u8, (i & 255) as u8];
            let mut g = [0x45; 12];
            g[..4].copy_from_slice(&i.to_be_bytes());
            t.advance(Duration::from_millis(1));
            t.spdp(&spdp(g, &[src], None), ip(src));
            t.b.note_finding(&g, Severity::Critical);
        }
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![sa(XIP)]);
        assert!(t.b.history.len() <= MAX_LOCATOR_HISTORY);
    }

    #[test]
    fn vouch_external_applies_the_same_filters_and_never_overrides_the_table() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P1, &[RIP], None), ip(RIP)).is_empty());
        let lo = [127, 0, 0, 1];
        let q =
            t.b.vouch_external(&P3, &[sa(XIP), sa(RIP), sa(lo)], Some(ip(XIP)), t.now);
        assert_eq!(q.locators, vec![sa(XIP)]);
        assert!(q.guid_only);
        let q = t.b.vouch_external(&P3, &[sa(RIP)], Some(ip(RIP)), t.now);
        assert_eq!(q.excluded, vec![(sa(RIP), excluded::PROFILED)]);
        // A prefix the table knows: the table's answer (here contested).
        t.spdp(&spdp(P1, &[XIP], None), ip(XIP));
        assert!(t.b.is_contested(&P1));
        let q = t.b.vouch_external(&P1, &[sa(XIP)], Some(ip(XIP)), t.now);
        assert!(q.known && q.locators.is_empty() && !q.guid_only, "{q:?}");
    }

    #[test]
    fn ranks_and_the_per_source_cap_keep_a_rogue_under_a_spray() {
        let mut t = T::new(BindingOptions::default());
        assert!(t.spdp(&spdp(P2, &[XIP], None), ip(XIP)).is_empty());
        assert_eq!(t.b.locator_rank(&P2), Some(Rank::SpdpOnly));
        t.b.note_finding(&P2, Severity::Critical);
        t.b.note_finding(&P2, Severity::High);
        assert_eq!(t.b.locator_rank(&P2), Some(Rank::Critical), "never lowered");
        // A spray from one address keeps at most its own share.
        let spray = [10, 0, 0, 77];
        for i in 0..(MAX_LOCATOR_HISTORY as u32 + 200) {
            let mut g = [0x44; 12];
            g[..4].copy_from_slice(&i.to_be_bytes());
            t.advance(Duration::from_millis(1));
            t.spdp(&spdp(g, &[spray], None), ip(spray));
            t.b.note_finding(&g, Severity::Critical);
        }
        assert!(t.b.history.len() <= MAX_LOCATOR_HISTORY_PER_SOURCE + 1);
        assert_eq!(t.b.quarantine_locators(&P2, t.now), vec![sa(XIP)]);
        t.b.note_soc_reference(&P2);
        assert_eq!(t.b.locator_rank(&P2), Some(Rank::SocReferenced));
    }
}
