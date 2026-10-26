//! Classic BPF socket filter for RTPS, built and checked as pure data.
//!
//! [`rtps_filter_program`] compiles an [`RtpsFilter`] into a classic BPF
//! (cBPF) program for `SO_ATTACH_FILTER` on an `AF_PACKET`/`SOCK_DGRAM`
//! socket, where packet offset 0 is the start of the IP header. Dropping
//! non-RTPS traffic in the kernel means the sensor only pays a copy for
//! candidate packets.
//!
//! The program accepts:
//! - IPv4 UDP with a destination port inside the port map's ranges, or (if the
//!   mode includes the magic) whose payload starts with `"RTPS"`, or whose
//!   source or destination port is one of the filter's Unitree legacy UDP
//!   ports ([`RtpsFilter::legacy_udp_ports`], empty by default);
//! - IPv4 UDP *fragments* (MF set or offset != 0) — the UDP header or magic
//!   may not be in this fragment, so user space reassembles and decides;
//! - IPv6 UDP directly after the fixed header, same port/magic rule;
//! - IPv6 packets whose first next-header is an extension header (incl.
//!   fragment): cBPF cannot loop over the chain, so user space decides. These
//!   are rare on a robot LAN;
//! - TCP (IPv4 first fragments / unfragmented, IPv6 directly after the fixed
//!   header) to or from the Zenoh port 7447 with **SYN, FIN or RST** set,
//!   cut to [`ZENOH_SNAP_LEN`] bytes: connection set-up and tear-down of a
//!   middleware the sensor cannot decode, so user space can report the blind
//!   spot ([`crate::middleware`]) without copying the session's data stream.
//!
//! Everything else is dropped. The user-space [`RtpsFilter`] is always applied
//! afterwards as well, so the kernel filter is an optimisation, never the
//! only check — and it is also the fallback when attaching fails.
//!
//! Every jump in the program is short and forward (each port range carries
//! its own `ret`), so the program never needs a jump offset above 255, and
//! [`BpfProgram::validate`] re-checks the same invariants the kernel's
//! `sk_chk_filter` enforces. [`BpfProgram::run`] is a small interpreter used
//! by the tests (and available to tools) to check the program's *behaviour*
//! against the user-space filter on concrete packets.

use crate::ports::{MatchMode, RtpsFilter, RTPS_MAGIC};

/// One cBPF instruction, layout-compatible with Linux `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Instruction classes.
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
// Load sizes.
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
// Load modes.
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MSH: u16 = 0xa0;
// ALU ops.
pub const BPF_AND: u16 = 0x50;
pub const BPF_RSH: u16 = 0x70;
// Jumps.
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
// Operand source.
pub const BPF_K: u16 = 0x00;

/// Kernel limit on cBPF program length (`BPF_MAXINSNS`).
pub const BPF_MAXINSNS: usize = 4096;

/// Snap length returned on accept: keep the whole packet.
pub const ACCEPT_LEN: u32 = 0x0004_0000;

/// Snap length of an accepted Zenoh TCP control segment (headers only).
pub const ZENOH_SNAP_LEN: u32 = 128;

/// A validated-on-construction cBPF program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpfProgram {
    insns: Vec<SockFilter>,
}

/// Why a program could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BpfError {
    TooLong(usize),
    Empty,
    JumpOutOfRange { at: usize },
    UnknownOpcode { at: usize, code: u16 },
    NoFinalReturn,
}

impl std::fmt::Display for BpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong(n) => write!(f, "program has {n} instructions (max {BPF_MAXINSNS})"),
            Self::Empty => f.write_str("empty program"),
            Self::JumpOutOfRange { at } => write!(f, "jump at {at} leaves the program"),
            Self::UnknownOpcode { at, code } => write!(f, "unsupported opcode {code:#06x} at {at}"),
            Self::NoFinalReturn => f.write_str("last instruction is not a return"),
        }
    }
}

impl std::error::Error for BpfError {}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

const LDB_ABS: u16 = BPF_LD | BPF_B | BPF_ABS; // 0x30
const LDH_ABS: u16 = BPF_LD | BPF_H | BPF_ABS; // 0x28
const LDH_IND: u16 = BPF_LD | BPF_H | BPF_IND; // 0x48
const LDB_IND: u16 = BPF_LD | BPF_B | BPF_IND; // 0x50
const LDW_IND: u16 = BPF_LD | BPF_W | BPF_IND; // 0x40
const LDXB_MSH: u16 = BPF_LDX | BPF_B | BPF_MSH; // 0xb1
const LDX_IMM: u16 = BPF_LDX | BPF_W | BPF_IMM; // 0x01
const RSH_K: u16 = BPF_ALU | BPF_RSH | BPF_K; // 0x74
const JA: u16 = BPF_JMP | BPF_JA; // 0x05
const JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K; // 0x15
const JGT_K: u16 = BPF_JMP | BPF_JGT | BPF_K; // 0x25
const JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K; // 0x35
const JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K; // 0x45
const RET_K: u16 = BPF_RET | BPF_K; // 0x06

impl BpfProgram {
    /// Wrap raw instructions after [`validate`](Self::validate)-ing them.
    pub fn new(insns: Vec<SockFilter>) -> Result<Self, BpfError> {
        let p = Self { insns };
        p.validate()?;
        Ok(p)
    }

    pub fn instructions(&self) -> &[SockFilter] {
        &self.insns
    }

    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// The structural checks the kernel performs: length, only opcodes this
    /// module emits (a strict subset of cBPF), all jump targets inside the
    /// program, final instruction a return.
    pub fn validate(&self) -> Result<(), BpfError> {
        let n = self.insns.len();
        if n == 0 {
            return Err(BpfError::Empty);
        }
        if n > BPF_MAXINSNS {
            return Err(BpfError::TooLong(n));
        }
        for (at, i) in self.insns.iter().enumerate() {
            let next = at + 1;
            match i.code {
                LDB_ABS | LDH_ABS | LDH_IND | LDB_IND | LDW_IND | LDXB_MSH | LDX_IMM | RSH_K
                | RET_K => {}
                JEQ_K | JGT_K | JGE_K | JSET_K => {
                    if next + usize::from(i.jt.max(i.jf)) >= n {
                        return Err(BpfError::JumpOutOfRange { at });
                    }
                }
                JA => {
                    if (next as u64) + u64::from(i.k) >= n as u64 {
                        return Err(BpfError::JumpOutOfRange { at });
                    }
                }
                AND_K => {}
                code => return Err(BpfError::UnknownOpcode { at, code }),
            }
        }
        if self.insns[n - 1].code & 0x07 != BPF_RET {
            return Err(BpfError::NoFinalReturn);
        }
        Ok(())
    }

    /// Interpret the program on `packet` (offset 0 = IP header) and return
    /// the accepted length (0 = drop), with kernel semantics: an out-of-bounds
    /// load drops the packet.
    pub fn run(&self, packet: &[u8]) -> u32 {
        let (mut a, mut x) = (0u32, 0u32);
        let mut pc = 0usize;
        let load = |off: u64, size: usize| -> Option<u32> {
            let off = usize::try_from(off).ok()?;
            let b = packet.get(off..off.checked_add(size)?)?;
            Some(b.iter().fold(0u32, |acc, &v| (acc << 8) | u32::from(v)))
        };
        while let Some(i) = self.insns.get(pc) {
            pc += 1;
            match i.code {
                LDB_ABS => match load(u64::from(i.k), 1) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDH_ABS => match load(u64::from(i.k), 2) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDH_IND => match load(u64::from(x) + u64::from(i.k), 2) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDB_IND => match load(u64::from(x) + u64::from(i.k), 1) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDW_IND => match load(u64::from(x) + u64::from(i.k), 4) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDXB_MSH => match load(u64::from(i.k), 1) {
                    Some(v) => x = (v & 0x0f) * 4,
                    None => return 0,
                },
                LDX_IMM => x = i.k,
                RSH_K => a = a.checked_shr(i.k).unwrap_or(0),
                AND_K => a &= i.k,
                JA => pc = pc.saturating_add(i.k as usize),
                JEQ_K | JGT_K | JGE_K | JSET_K => {
                    let taken = match i.code {
                        JEQ_K => a == i.k,
                        JGT_K => a > i.k,
                        JGE_K => a >= i.k,
                        _ => a & i.k != 0,
                    };
                    pc += usize::from(if taken { i.jt } else { i.jf });
                }
                RET_K => return i.k,
                _ => return 0,
            }
        }
        0
    }
}

const AND_K: u16 = BPF_ALU | BPF_AND | BPF_K; // 0x54

/// Compile `filter` to a cBPF program for an `AF_PACKET` `SOCK_DGRAM` socket.
pub fn rtps_filter_program(filter: &RtpsFilter) -> Result<BpfProgram, BpfError> {
    let use_ports = matches!(filter.mode, MatchMode::PortsOnly | MatchMode::PortsOrMagic);
    let use_magic = matches!(filter.mode, MatchMode::MagicOnly | MatchMode::PortsOrMagic);
    let accept = stmt(RET_K, ACCEPT_LEN);
    let drop = stmt(RET_K, 0);

    let mut p = vec![
        // Version nibble.
        stmt(LDB_ABS, 0),
        stmt(RSH_K, 4),
    ];
    // IPv4 block: 9 instructions after this jeq; on mismatch skip to IPv6.
    let v4 = [
        stmt(LDB_ABS, 9),           // protocol
        jump(JEQ_K, 17, 1, 0),      // UDP?
        stmt(JA, 0),                // patched: not UDP -> the TCP/v4 block
        stmt(LDH_ABS, 6),           // flags + fragment offset
        jump(JSET_K, 0x3fff, 0, 1), // MF or offset != 0 -> fragment
        accept,                     //
        stmt(LDXB_MSH, 0),          // X = IHL * 4
        stmt(JA, 0),                // patched: jump to the shared port check
    ];
    p.push(jump(JEQ_K, 4, 0, v4.len() as u8));
    let ja_at = p.len() + v4.len() - 1;
    let tcp4_ja = p.len() + 2;
    p.extend_from_slice(&v4);
    // IPv6 block (A still holds the version).
    p.extend_from_slice(&[
        jump(JEQ_K, 6, 1, 0),
        drop,
        stmt(LDB_ABS, 6),      // next header
        jump(JEQ_K, 17, 7, 0), // UDP -> ldx #40
        jump(JEQ_K, 44, 5, 0), // fragment       -> accept
        jump(JEQ_K, 0, 4, 0),  // hop-by-hop     -> accept
        jump(JEQ_K, 43, 3, 0), // routing        -> accept
        jump(JEQ_K, 60, 2, 0), // dest options   -> accept
        jump(JEQ_K, 51, 1, 0), // AH             -> accept
        stmt(JA, 0),           // patched: anything else -> the TCP/v6 block
        accept,
        stmt(LDX_IMM, 40),
    ]);
    let tcp6_ja = p.len() - 3;
    // Shared UDP check, X = offset of the UDP header.
    let shared = p.len();
    p[ja_at].k = (shared - (ja_at + 1)) as u32;
    if use_ports {
        p.push(stmt(LDH_IND, 2)); // destination port
        for (lo, hi) in filter.ports.port_ranges() {
            p.push(jump(JGE_K, u32::from(lo), 0, 2));
            p.push(jump(JGT_K, u32::from(hi), 1, 0));
            p.push(accept);
        }
    }
    // Unitree legacy UDP (source or destination port), when configured.
    for port in &filter.legacy_udp_ports {
        let port = u32::from(*port);
        p.extend_from_slice(&[
            stmt(LDH_IND, 2), // destination port
            jump(JEQ_K, port, 0, 1),
            accept,
            stmt(LDH_IND, 0), // source port
            jump(JEQ_K, port, 0, 1),
            accept,
        ]);
    }
    if use_magic {
        // Last: an out-of-bounds load drops, which is right for a payload
        // shorter than the magic.
        p.push(stmt(LDW_IND, 8));
        p.push(jump(JEQ_K, u32::from_be_bytes(RTPS_MAGIC), 0, 1));
        p.push(accept);
    }
    p.push(drop);
    // TCP control segments of the Zenoh port (see the module docs). A holds
    // the IPv4 protocol / IPv6 next header on entry.
    let zenoh = u32::from(crate::middleware::ZENOH_PORT);
    let tcp4 = p.len();
    p.extend_from_slice(&[
        jump(JEQ_K, 6, 0, 4), // TCP?
        stmt(LDH_ABS, 6),
        jump(JSET_K, 0x1fff, 2, 0), // non-first fragment: no ports
        stmt(LDXB_MSH, 0),
        stmt(JA, 5), // -> tcp shared (after the v6 block)
        drop,
    ]);
    let tcp6 = p.len();
    p.extend_from_slice(&[
        jump(JEQ_K, 6, 0, 2), // TCP?
        stmt(LDX_IMM, 40),
        stmt(JA, 1), // -> tcp shared
        drop,
    ]);
    p.extend_from_slice(&[
        stmt(LDB_IND, 13),        // TCP flags
        jump(JSET_K, 0x07, 0, 5), // FIN | SYN | RST
        stmt(LDH_IND, 0),         // source port
        jump(JEQ_K, zenoh, 4, 0), //
        stmt(LDH_IND, 2),         // destination port
        jump(JEQ_K, zenoh, 2, 0), //
        drop,
        drop,
        stmt(RET_K, ZENOH_SNAP_LEN),
    ]);
    p[tcp4_ja].k = (tcp4 - (tcp4_ja + 1)) as u32;
    p[tcp6_ja].k = (tcp6 - (tcp6_ja + 1)) as u32;
    BpfProgram::new(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode_ip, Decoded};
    use crate::ports::RtpsPortMap;
    use crate::synth;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn opcode_encoding_matches_tcpdump() {
        // Values as printed by `tcpdump -dd` for the equivalent statements.
        assert_eq!(LDH_ABS, 0x28); // ldh [k]
        assert_eq!(LDB_ABS, 0x30); // ldb [k]
        assert_eq!(LDH_IND, 0x48); // ldh [x + k]
        assert_eq!(LDW_IND, 0x40); // ld [x + k]
        assert_eq!(LDXB_MSH, 0xb1); // ldxb 4*([k]&0xf)
        assert_eq!(LDX_IMM, 0x01); // ldx #k
        assert_eq!(RSH_K, 0x74); // rsh #k
        assert_eq!(AND_K, 0x54); // and #k
        assert_eq!(JA, 0x05); // ja
        assert_eq!(JEQ_K, 0x15); // jeq #k
        assert_eq!(JGT_K, 0x25); // jgt #k
        assert_eq!(JGE_K, 0x35); // jge #k
        assert_eq!(JSET_K, 0x45); // jset #k
        assert_eq!(RET_K, 0x06); // ret #k
        assert_eq!(std::mem::size_of::<SockFilter>(), 8);
    }

    #[test]
    fn program_head_is_exact() {
        let prog = rtps_filter_program(&RtpsFilter::new(
            RtpsPortMap::new([0], 2),
            MatchMode::PortsOrMagic,
        ))
        .unwrap();
        let i = prog.instructions();
        let expect_head = [
            (0x30, 0, 0, 0),      // ldb [0]
            (0x74, 0, 0, 4),      // rsh #4
            (0x15, 0, 8, 4),      // jeq #4, else +8 to IPv6
            (0x30, 0, 0, 9),      // ldb [9]
            (0x15, 1, 0, 17),     // jeq #17
            (0x05, 0, 0, i[5].k), // ja -> TCP/v4 (checked below)
            (0x28, 0, 0, 6),      // ldh [6]
            (0x45, 0, 1, 0x3fff), // jset #0x3fff
            (0x06, 0, 0, ACCEPT_LEN),
            (0xb1, 0, 0, 0),  // ldxb 4*([0]&0xf)
            (0x05, 0, 0, 12), // ja -> shared (skip 12 IPv6 instructions)
            (0x15, 1, 0, 6),  // jeq #6
        ];
        for (n, &(code, jt, jf, k)) in expect_head.iter().enumerate() {
            assert_eq!(i[n], SockFilter { code, jt, jf, k }, "instruction {n}");
        }
        assert_eq!(i[20].code, JA, "other IPv6 next headers -> TCP/v6");
        // Shared tail: ldh [x+2], 2 ranges * 3, ld [x+8], jeq RTPS, ret, ret 0,
        // then the 6 + 4 + 9 instructions of the Zenoh TCP blocks.
        let shared = &i[23..];
        assert_eq!(6 + i[5].k as usize, 23 + 11, "ja lands on the TCP/v4 block");
        assert_eq!(
            21 + i[20].k as usize,
            23 + 11 + 6,
            "ja lands on the TCP/v6 block"
        );
        let shared = &shared[..shared.len() - 19];
        assert_eq!(
            shared[0],
            SockFilter {
                code: 0x48,
                jt: 0,
                jf: 0,
                k: 2
            }
        );
        assert_eq!(
            shared[1],
            SockFilter {
                code: 0x35,
                jt: 0,
                jf: 2,
                k: 7400
            }
        );
        assert_eq!(
            shared[2],
            SockFilter {
                code: 0x25,
                jt: 1,
                jf: 0,
                k: 7401
            }
        );
        assert_eq!(
            shared[4],
            SockFilter {
                code: 0x35,
                jt: 0,
                jf: 2,
                k: 7410
            }
        );
        assert_eq!(
            shared[5],
            SockFilter {
                code: 0x25,
                jt: 1,
                jf: 0,
                k: 7415
            }
        );
        assert_eq!(
            shared[7],
            SockFilter {
                code: 0x40,
                jt: 0,
                jf: 0,
                k: 8
            }
        );
        assert_eq!(
            shared[8],
            SockFilter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: 0x5254_5053
            }
        );
        assert_eq!(shared.len(), 11);
        assert_eq!(
            *i.last().unwrap(),
            SockFilter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: ZENOH_SNAP_LEN
            }
        );
        assert_eq!(LDB_IND, 0x50); // ldb [x + k]
    }

    /// TCP with the given flags (no options): synth builds UDP, patched.
    fn tcp(src: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = synth::ipv4_udp(src, src, sport, dport, &[0u8; 12]);
        p[9] = 6;
        p[20 + 13] = flags;
        p
    }

    #[test]
    fn zenoh_tcp_control_segments_pass_cut_data_segments_do_not() {
        let prog = rtps_filter_program(&RtpsFilter::default()).unwrap();
        let a = Ipv4Addr::new(10, 0, 0, 1);
        for flags in [0x02, 0x12, 0x11, 0x04] {
            assert_eq!(prog.run(&tcp(a, 40000, 7447, flags)), ZENOH_SNAP_LEN);
            assert_eq!(prog.run(&tcp(a, 7447, 40000, flags)), ZENOH_SNAP_LEN);
        }
        // Data / pure ACK segments, and other ports: dropped.
        assert_eq!(prog.run(&tcp(a, 40000, 7447, 0x18)), 0);
        assert_eq!(prog.run(&tcp(a, 40000, 7447, 0x10)), 0);
        assert_eq!(prog.run(&tcp(a, 40000, 22, 0x02)), 0);
        // A non-first IPv4 fragment carries no TCP header.
        let mut frag = tcp(a, 40000, 7447, 0x02);
        frag[7] = 1;
        assert_eq!(prog.run(&frag), 0);
        // IPv6 TCP directly after the fixed header.
        let s6: Ipv6Addr = "fd00::1".parse().unwrap();
        let mut v6 = synth::ipv6_udp(s6, s6, 40000, 7447, &[], &[0u8; 12]);
        v6[6] = 6;
        v6[40 + 13] = 0x02;
        assert_eq!(prog.run(&v6), ZENOH_SNAP_LEN);
        v6[40 + 13] = 0x18;
        assert_eq!(prog.run(&v6), 0);
        // What the kernel keeps is still recognised in user space.
        let cut = &tcp(a, 40000, 7447, 0x02)[..ZENOH_SNAP_LEN.min(32) as usize];
        assert!(crate::middleware::classify_tcp_frame(crate::decode::LinkType::RAW, cut).is_some());
    }

    #[test]
    fn validate_rejects_bad_programs() {
        assert_eq!(BpfProgram::new(vec![]), Err(BpfError::Empty));
        assert_eq!(
            BpfProgram::new(vec![jump(JEQ_K, 1, 5, 0), stmt(RET_K, 0)]),
            Err(BpfError::JumpOutOfRange { at: 0 })
        );
        assert_eq!(
            BpfProgram::new(vec![stmt(JA, 1), stmt(RET_K, 0)]),
            Err(BpfError::JumpOutOfRange { at: 0 })
        );
        assert_eq!(
            BpfProgram::new(vec![stmt(0x07, 0), stmt(RET_K, 0)]),
            Err(BpfError::UnknownOpcode { at: 0, code: 0x07 })
        );
        assert_eq!(
            BpfProgram::new(vec![stmt(LDX_IMM, 0)]),
            Err(BpfError::NoFinalReturn)
        );
        assert_eq!(
            BpfProgram::new(vec![stmt(RET_K, 0); BPF_MAXINSNS + 1]),
            Err(BpfError::TooLong(BPF_MAXINSNS + 1))
        );
        assert!(!BpfError::Empty.to_string().is_empty());
    }

    #[test]
    fn all_domains_program_fits_the_kernel_limit() {
        for mode in [
            MatchMode::PortsOnly,
            MatchMode::MagicOnly,
            MatchMode::PortsOrMagic,
        ] {
            let prog =
                rtps_filter_program(&RtpsFilter::new(RtpsPortMap::all_domains(), mode)).unwrap();
            assert!(prog.len() <= BPF_MAXINSNS);
            assert!(!prog.is_empty());
        }
    }

    /// The kernel filter must never drop what the user-space filter accepts
    /// (fragments and IPv6 extension chains are allowed to pass through).
    #[test]
    fn interpreter_agrees_with_userspace_filter() {
        let maps = [RtpsPortMap::new([0], 4), RtpsPortMap::new([0, 1, 7], 119)];
        let s4 = Ipv4Addr::new(10, 0, 0, 1);
        let d4 = Ipv4Addr::new(10, 0, 0, 2);
        let s6: Ipv6Addr = "fd00::1".parse().unwrap();
        let d6: Ipv6Addr = "fd00::2".parse().unwrap();
        let payloads: [&[u8]; 4] = [b"RTPS\x02\x03\x01\x0f", b"hello world", b"RTP", b""];
        let ports = [
            7400u16, 7401, 7402, 7409, 7410, 7411, 7418, 7419, 7420, 7650, 7660, 9150, 9160, 5353,
            0, 65535,
        ];
        for map in maps {
            for mode in [
                MatchMode::PortsOnly,
                MatchMode::MagicOnly,
                MatchMode::PortsOrMagic,
            ] {
                let filter = RtpsFilter::new(map.clone(), mode);
                let prog = rtps_filter_program(&filter).unwrap();
                for &port in &ports {
                    for payload in payloads {
                        let mut packets = vec![
                            synth::ipv4_udp(s4, d4, 50000, port, payload),
                            synth::ipv6_udp(s6, d6, 50000, port, &[], payload),
                        ];
                        // IPv4 with options moves the UDP header.
                        let mut opt = synth::ipv4_udp(s4, d4, 50000, port, payload);
                        opt.splice(20..20, [1u8, 1, 1, 0]);
                        opt[0] = 0x46;
                        let tl = opt.len() as u16;
                        opt[2..4].copy_from_slice(&tl.to_be_bytes());
                        packets.push(opt);
                        for pkt in packets {
                            let user = match decode_ip(&pkt) {
                                Ok(Decoded::Udp(u)) => filter.matches(&u),
                                other => panic!("{other:?}"),
                            };
                            let kernel = prog.run(&pkt) != 0;
                            assert_eq!(
                                kernel, user,
                                "mode {mode:?} port {port} payload {payload:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// With Unitree legacy ports the kernel filter accepts exactly what the
    /// user-space filter accepts as RTPS **or** legacy, in both directions
    /// (source or destination port), and nothing more.
    #[test]
    fn interpreter_agrees_with_userspace_filter_with_legacy_ports() {
        let s4 = Ipv4Addr::new(192, 168, 123, 161);
        let d4 = Ipv4Addr::new(192, 168, 123, 15);
        let s6: Ipv6Addr = "fd00::1".parse().unwrap();
        let d6: Ipv6Addr = "fd00::2".parse().unwrap();
        let payloads: [&[u8]; 3] = [b"RTPS\x02\x03\x01\x0f", &[0xfe; 129], b""];
        let ports = [8007u16, 8080, 8082, 8090, 7400, 7411, 5353, 0, 65535];
        for mode in [
            MatchMode::PortsOnly,
            MatchMode::MagicOnly,
            MatchMode::PortsOrMagic,
        ] {
            let filter = RtpsFilter::new(RtpsPortMap::new([0], 4), mode)
                .with_legacy_udp_ports([8007, 8080, 8082, 8090]);
            let prog = rtps_filter_program(&filter).unwrap();
            prog.validate().unwrap();
            for &sport in &ports {
                for &dport in &ports {
                    for payload in payloads {
                        for pkt in [
                            synth::ipv4_udp(s4, d4, sport, dport, payload),
                            synth::ipv6_udp(s6, d6, sport, dport, &[], payload),
                        ] {
                            let user = match decode_ip(&pkt) {
                                Ok(Decoded::Udp(u)) => filter.matches(&u) || filter.is_legacy(&u),
                                other => panic!("{other:?}"),
                            };
                            let kernel = prog.run(&pkt) != 0;
                            assert_eq!(
                                kernel, user,
                                "mode {mode:?} {sport}->{dport} payload {payload:?}"
                            );
                        }
                    }
                }
            }
        }
        // Without legacy ports nothing changes.
        let plain = RtpsFilter::new(RtpsPortMap::new([0], 4), MatchMode::PortsOrMagic);
        let legacy = synth::ipv4_udp(s4, d4, 8082, 8090, &[0xfe; 129]);
        assert_eq!(rtps_filter_program(&plain).unwrap().run(&legacy), 0);
    }

    #[test]
    fn interpreter_passes_fragments_and_ext_headers_drops_others() {
        let prog = rtps_filter_program(&RtpsFilter::default()).unwrap();
        let s4 = Ipv4Addr::new(10, 0, 0, 1);
        let ip = synth::ipv4_udp(s4, s4, 1, 5555, &[0u8; 64]);
        for f in synth::ipv4_fragment(&ip, 32) {
            assert_ne!(prog.run(&f), 0);
        }
        let s6: Ipv6Addr = "fd00::1".parse().unwrap();
        let ext = synth::ipv6_udp(s6, s6, 1, 5555, &[(60, 8)], b"nope");
        assert_ne!(prog.run(&ext), 0, "extension chains go to user space");
        let mut tcp = synth::ipv4_udp(s4, s4, 1, 7410, b"RTPS");
        tcp[9] = 6;
        assert_eq!(prog.run(&tcp), 0);
        let mut icmp6 = synth::ipv6_udp(s6, s6, 1, 7410, &[], b"RTPS");
        icmp6[6] = 58;
        assert_eq!(prog.run(&icmp6), 0);
        assert_eq!(prog.run(&[0x20; 40]), 0, "neither v4 nor v6");
        assert_eq!(prog.run(&[]), 0, "empty packet: out-of-bounds load drops");
        assert_eq!(prog.run(&[0x45, 0, 0]), 0);
    }
}
