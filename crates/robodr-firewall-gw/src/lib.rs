//! # RoboDR in-path Motion Firewall gateway
//!
//! An **inline bridge** on the sensor box: two NICs bridged (controller side
//! / robot side), `br_netfilter` hands every UDP datagram of the configured
//! motion channels that **enters from the controller side** to an NFQUEUE,
//! and this crate decides each one with `robodr-firewall` and answers
//! ACCEPT, DROP, or ACCEPT with a same-length rewritten payload. See the
//! crate README for deployment, the ruleset and the measured latency.
//!
//! **Not a safety-rated device.** It is a cyber-security control in front of
//! the robot's own safety functions, which remain primary (see the README).
//!
//! ## Pipeline ([`Gateway::process`])
//!
//! ```text
//! IPv4/UDP (ip)  ─► legacy port? ─► Go1 HighCmd / LowCmd (legacy)        ─┐
//!                └► DDS port?    ─► strict RTPS walk (rtps)               │
//!                                   ├ builtin DATA → discovery (SEDP/SPDP)│
//!                                   └ user DATA → writer → channel?       │
//!                                       └ LowCmd_ (lowcmd) / Request_ (sport)
//!                                            decide (robodr-firewall) ────┤
//!                                            pass / rewrite / suppress    │
//! UDP checksum refreshed if anything changed ◄────────────────────────────┘
//! ```
//!
//! ## What "hold" means on the wire
//!
//! The firewall's substitutes (hold the last accepted frame with `dq = 0`;
//! the damping frame on non-humanoids; a zero / held twist) are written
//! **into the rejected sample itself**: same RTPS submessage, same writer
//! GUID, same sequence number, same `INFO_TS` and inline QoS, same payload
//! length and representation, new content with the Unitree CRC recomputed.
//! The DDS reader on the robot then delivers it as that writer's next
//! sample. The gateway never originates a datagram and never invents a
//! sequence number:
//!
//! - **Replaying the last accepted datagram does not work**: its sequence
//!   number is already delivered, so the robot's reader discards it as a
//!   duplicate (best-effort and reliable alike).
//! - **Re-sending it with a fresh sequence number would corrupt the
//!   writer's stream**: the writer's own next sample would carry the same
//!   number and be discarded as a duplicate, and a reliable writer's
//!   HEARTBEAT / GAP state would contradict what the reader holds.
//!
//! So a hold is emitted exactly when the protected stream itself delivers a
//! sample to carry it: at most one per incoming frame, and never while the
//! stream is silent. When the firewall emits **nothing** (foreign source
//! with `drop`, a frame that arrived too early, a humanoid channel with no
//! frame accepted yet) the sample is **suppressed**: its submessage becomes
//! a PAD of the same length, so receivers skip it as if it had been lost in
//! transit (no forged GAP: a GAP for a spoofed high sequence number could
//! make a best-effort reader skip the real writer's samples). The rest of
//! the datagram (other samples, HEARTBEATs, INFO_*) is untouched.
//!
//! Invariant on a humanoid joint channel (enforce mode): every `LowCmd_`
//! the gateway forwards is either an accepted (passed or limited) frame or a
//! hold of the last accepted frame, so whatever the robot executes when a
//! tick is suppressed is the last frame it received, which is one of
//! those. Persistent silence (the controller stops, or only rejected
//! samples arrive faster than the substitute interval allows) is covered by
//! the robot's own command-timeout behaviour, as when the controller fails.
//!
//! ## Sequence numbers and writer binding
//!
//! Per writer GUID and channel the gateway keeps the stream's state as the
//! robot's reader sees it: the highest sequence number forwarded under
//! that GUID, the payload forwarded for the last 8 numbers, and the
//! (source IP, source MAC) the stream was last forwarded from (its
//! binding). The GUID is a claim, so only a sample of an authorised source
//! **from the bound (IP, MAC)** changes that state:
//!
//! - a sample whose number is not newer (a reliable retransmission, or a
//!   replay) is not decided again: the cached output is re-emitted byte
//!   for byte if the slot has the same length, otherwise it is suppressed;
//! - a foreign sample is decided (recorded) but never changes the state,
//!   and no substitute is written into it under an authorised GUID;
//! - the same authorised GUID from another (IP, MAC) is suppressed while
//!   the bound side is live (`rtps.binding_takeover_ns`);
//! - a jump of more than `rtps.max_sn_jump` is suppressed until the next
//!   sample of the same binding confirms it, so no single forwarded sample
//!   can push the robot reader's expected number far past the genuine
//!   writer's;
//! - a lower number after an SEDP announcement / removal of the writer from
//!   the bound IP is a writer restart (fresh state), once.
//!
//! An attacker that sends with the controller's own IP **and** MAC cannot
//! be told apart; see the README for what that leaves.
//!
//! ## Undecidable samples
//!
//! A payload of an enforced channel that does not decode strictly
//! (truncated, non-canonical CDR, trailing junk) — or a go `LowCmd_` whose
//! `bms_cmd.off` is not zero (battery off) on a channel without
//! `allow_battery_off` — is decided as an **integrity failure**: the
//! firewall gets a frame whose CRC is reported invalid, so its source, rate
//! and substitute rules apply (a foreign writer's garbage is dropped; an
//! authorised writer's is replaced by the hold / damping substitute where
//! the slot can carry one, else suppressed). DATA_FRAG, key-only and
//! non-standard samples of an enforced channel are suppressed (the Unitree
//! SDK does not fragment `LowCmd_` at Cyclone DDS's default 1344-octet
//! fragment size; a fragmented one is a misconfiguration or an attack), and
//! so are those of a writer the gateway has no classification for (the
//! content probe cannot read them). A datagram that is not decidable as a
//! whole follows `rtps.malformed_datagram` (default drop).

// S10: `unsafe` is denied crate-wide. Only the FFI items std cannot replace
// carry a local `#[allow(unsafe_code)]` (the NFQUEUE netlink socket in
// `nfq::socket`; `signal(2)` and `clock_gettime` in `sys`), each with a
// `// SAFETY:` comment on every block.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// gateway (systemd restarts it; while it is down the kernel applies
// `on_gateway_down`). Non-test code has no unwrap / expect / panic!-family
// call; slice indexing and arithmetic are left to review and fuzzing
// (fuzz/README.md, `firewall_gw_packet`).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod config;
pub mod discovery;
pub mod gateway;
pub mod ip;
pub mod legacy;
pub mod lowcmd;
pub mod nfq;
pub mod round;
pub mod rtps;
pub mod ruleset;
pub mod runtime;
pub mod sport;
pub mod sys;
#[cfg(feature = "testkit")]
#[doc(hidden)]
pub mod testkit;

pub use config::{Codec, GatewayConfig, GatewayMode, OnGatewayDown};
pub use gateway::{Gateway, GatewayStats, PacketMeta, Verdict};
