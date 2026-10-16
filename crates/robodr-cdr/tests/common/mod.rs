//! A tiny, independent CDR *encoder* used only by the tests.
//!
//! It is written separately from the crate's reader (no shared code) and is
//! itself pinned to the hand-derived byte vectors in `vectors.rs`: every
//! hand vector is also produced by this encoder and compared byte for byte.
//! That lets the round-trip / fuzz tests cover the larger types (Odometry,
//! Imu, JointTrajectory) whose full byte strings would be impractical to
//! write by hand.

#![allow(dead_code)]

use robodr_cdr::Representation;

pub const ALL_REPS: [Representation; 6] = [
    Representation::CdrBe,
    Representation::CdrLe,
    Representation::Cdr2Be,
    Representation::Cdr2Le,
    Representation::DCdr2Be,
    Representation::DCdr2Le,
];

/// Parses hand-written hex vectors: on each line, the leading
/// whitespace-separated tokens that are exactly two hex digits are bytes;
/// the first other token (`@12`, a word, ...) starts the line's comment.
pub fn hex(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in s.lines() {
        for tok in line.split_whitespace() {
            if tok.len() != 2 || !tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                break;
            }
            out.push(u8::from_str_radix(tok, 16).unwrap());
        }
    }
    out
}

pub struct Enc {
    rep: u16,
    options: u16,
    big: bool,
    xcdr2: bool,
    delimited: bool,
    pub body: Vec<u8>,
    stack: Vec<usize>,
}

impl Enc {
    pub fn new(rep: Representation) -> Self {
        let id = rep.id();
        Enc {
            rep: id,
            options: 0,
            big: id & 1 == 0,
            xcdr2: id >= 0x10,
            delimited: id == 0x14 || id == 0x15,
            body: Vec::new(),
            stack: Vec::new(),
        }
    }

    pub fn align(&mut self, size: usize) {
        let a = size.min(if self.xcdr2 { 4 } else { 8 });
        while !self.body.len().is_multiple_of(a) {
            self.body.push(0);
        }
    }

    pub fn u32(&mut self, v: u32) {
        self.align(4);
        let b = if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.body.extend_from_slice(&b);
    }

    pub fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }

    pub fn f64(&mut self, v: f64) {
        self.align(8);
        let b = if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.body.extend_from_slice(&b);
    }

    pub fn string(&mut self, s: &[u8]) {
        self.u32(s.len() as u32 + 1);
        self.body.extend_from_slice(s);
        self.body.push(0);
    }

    pub fn begin_dheader(&mut self) {
        self.align(4);
        self.stack.push(self.body.len());
        self.body.extend_from_slice(&[0; 4]);
    }

    pub fn end_dheader(&mut self) {
        let at = self.stack.pop().unwrap();
        let size = (self.body.len() - at - 4) as u32;
        let b = if self.big {
            size.to_be_bytes()
        } else {
            size.to_le_bytes()
        };
        self.body[at..at + 4].copy_from_slice(&b);
    }

    pub fn structure(&mut self, f: impl FnOnce(&mut Self)) {
        if self.delimited {
            self.begin_dheader();
            f(self);
            self.end_dheader();
        } else {
            f(self);
        }
    }

    pub fn nonprim_seq(&mut self, f: impl FnOnce(&mut Self)) {
        if self.xcdr2 {
            self.begin_dheader();
            f(self);
            self.end_dheader();
        } else {
            f(self);
        }
    }

    pub fn f64_seq(&mut self, v: &[f64]) {
        self.u32(v.len() as u32);
        for x in v {
            self.f64(*x);
        }
    }

    pub fn string_seq(&mut self, v: &[&[u8]]) {
        self.nonprim_seq(|e| {
            e.u32(v.len() as u32);
            for s in v {
                e.string(s);
            }
        });
    }

    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.body.len());
        out.extend_from_slice(&self.rep.to_be_bytes());
        out.extend_from_slice(&self.options.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    // ---- message encoders ----

    pub fn time(&mut self, sec: i32, nanosec: u32) {
        self.structure(|e| {
            e.i32(sec);
            e.u32(nanosec);
        });
    }

    pub fn header(&mut self, sec: i32, nanosec: u32, frame: &[u8]) {
        self.structure(|e| {
            e.time(sec, nanosec);
            e.string(frame);
        });
    }

    pub fn vec3(&mut self, v: [f64; 3]) {
        self.structure(|e| {
            for x in v {
                e.f64(x);
            }
        });
    }

    pub fn quat(&mut self, v: [f64; 4]) {
        self.structure(|e| {
            for x in v {
                e.f64(x);
            }
        });
    }

    pub fn twist(&mut self, lin: [f64; 3], ang: [f64; 3]) {
        self.structure(|e| {
            e.vec3(lin);
            e.vec3(ang);
        });
    }

    pub fn twist_stamped(&mut self, sec: i32, ns: u32, frame: &[u8], lin: [f64; 3], ang: [f64; 3]) {
        self.structure(|e| {
            e.header(sec, ns, frame);
            e.twist(lin, ang);
        });
    }

    pub fn f64_array(&mut self, v: &[f64]) {
        for x in v {
            self.f64(*x);
        }
    }
}

/// Test-side Odometry description.
pub struct OdomSpec<'a> {
    pub frame: &'a [u8],
    pub child: &'a [u8],
    pub position: [f64; 3],
    pub orientation: [f64; 4],
    pub pose_cov: [f64; 36],
    pub lin: [f64; 3],
    pub ang: [f64; 3],
    pub twist_cov: [f64; 36],
}

pub fn odometry(rep: Representation, o: &OdomSpec<'_>) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.header(10, 20, o.frame);
        e.string(o.child);
        e.structure(|e| {
            e.structure(|e| {
                e.vec3(o.position);
                e.quat(o.orientation);
            });
            e.f64_array(&o.pose_cov);
        });
        e.structure(|e| {
            e.twist(o.lin, o.ang);
            e.f64_array(&o.twist_cov);
        });
    });
    e.finish()
}

pub fn imu(rep: Representation, frame: &[u8], gyro: [f64; 3]) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.header(3, 4, frame);
        e.quat([0.0, 0.0, 0.0, 1.0]);
        e.f64_array(&[0.1; 9]);
        e.vec3(gyro);
        e.f64_array(&[0.2; 9]);
        e.vec3([0.0, 0.0, 9.81]);
        e.f64_array(&[0.3; 9]);
    });
    e.finish()
}

pub fn joint_state(
    rep: Representation,
    names: &[&[u8]],
    pos: &[f64],
    vel: &[f64],
    eff: &[f64],
) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.header(0, 0, b"");
        e.string_seq(names);
        e.f64_seq(pos);
        e.f64_seq(vel);
        e.f64_seq(eff);
    });
    e.finish()
}

pub struct PointSpec<'a> {
    pub positions: &'a [f64],
    pub velocities: &'a [f64],
    pub accelerations: &'a [f64],
    pub effort: &'a [f64],
    pub sec: i32,
    pub nanosec: u32,
}

pub fn joint_trajectory(rep: Representation, names: &[&[u8]], points: &[PointSpec<'_>]) -> Vec<u8> {
    let mut e = Enc::new(rep);
    e.structure(|e| {
        e.header(5, 6, b"base_link");
        e.string_seq(names);
        e.nonprim_seq(|e| {
            e.u32(points.len() as u32);
            for p in points {
                e.structure(|e| {
                    e.f64_seq(p.positions);
                    e.f64_seq(p.velocities);
                    e.f64_seq(p.accelerations);
                    e.f64_seq(p.effort);
                    e.time(p.sec, p.nanosec);
                });
            }
        });
    });
    e.finish()
}

/// xorshift64* — std-only deterministic PRNG for the fuzz loops.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    pub fn f64_any(&mut self) -> f64 {
        match self.below(8) {
            0 => f64::NAN,
            1 => f64::INFINITY,
            2 => f64::NEG_INFINITY,
            3 => -0.0,
            4 => f64::from_bits(self.next()),
            _ => (self.next() % 2001) as f64 / 100.0 - 10.0,
        }
    }
}
