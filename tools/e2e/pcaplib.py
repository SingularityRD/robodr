"""Minimal pcap (classic, us or ns) reader/writer for the E2E traffic tools."""
import struct


def read(path):
    """[(t_seconds, frame_bytes)] and the link type."""
    d = open(path, "rb").read()
    magic, = struct.unpack("<I", d[:4])
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise ValueError(f"{path}: not a little-endian classic pcap")
    div = 1e9 if magic == 0xA1B23C4D else 1e6
    linktype, = struct.unpack("<I", d[20:24])
    out, off = [], 24
    while off + 16 <= len(d):
        ts, tf, cl, _ = struct.unpack("<IIII", d[off:off + 16])
        out.append((ts + tf / div, d[off + 16:off + 16 + cl]))
        off += 16 + cl
    return out, linktype


def write(path, frames, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for t, fr in frames:
            s = int(t); us = int(round((t - s) * 1e6))
            if us >= 1_000_000:
                s += 1; us -= 1_000_000
            f.write(struct.pack("<IIII", s, us, len(fr), len(fr)) + fr)


def loop(frames, times, gap=0.5):
    """`frames` repeated `times` times on one continuous timeline."""
    out, base = [], 0.0
    t0 = frames[0][0]
    span = frames[-1][0] - t0
    for _ in range(times):
        out += [(base + t - t0, fr) for t, fr in frames]
        base += span + gap
    return out
