"""Red-team helpers: netns switching, Ethernet/IPv4/UDP crafting, RTPS
mutation, spool/status observation."""
import collections, json, os, random, socket, struct, time

CLONE_NEWNET = 0x40000000


def netns(name):
    fd = os.open(f"/run/netns/{name}", os.O_RDONLY)
    os.setns(fd, CLONE_NEWNET)
    os.close(fd)


def packet_socket(ns, iface):
    """An AF_PACKET socket bound to `iface` in netns `ns` (the calling
    thread returns to its netns afterwards)."""
    me = os.open("/proc/self/ns/net", os.O_RDONLY)
    netns(ns)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    os.setns(me, CLONE_NEWNET); os.close(me)
    return s


def send(s, frames, pps=1000):
    gap = 1.0 / pps if pps else 0
    for f in frames:
        s.send(f)
        if gap:
            time.sleep(gap)


def ip_csum(h):
    s = sum(struct.unpack("!10H", h[:20]))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def split(frame):
    """(eth, ip_header, udp_header, payload) of an Ethernet/IPv4/UDP frame."""
    ihl = (frame[14] & 0x0F) * 4
    ip = frame[14:14 + ihl]
    return frame[:14], ip, frame[14 + ihl:22 + ihl], frame[22 + ihl:]


def build(eth, ip, udp, payload, src=None, ident=None):
    """Re-assemble with correct lengths, IP checksum, UDP checksum 0."""
    ip = bytearray(ip[:20]); ip[0] = 0x45
    if src:
        ip[12:16] = socket.inet_aton(src)
    if ident is not None:
        ip[4:6] = struct.pack("!H", ident)
    ip[6:8] = b"\x00\x00"  # no fragmentation flags
    ip[2:4] = struct.pack("!H", 20 + 8 + len(payload))
    ip[10:12] = b"\x00\x00"; ip[10:12] = struct.pack("!H", ip_csum(bytes(ip)))
    udp = bytearray(udp[:8]); udp[4:6] = struct.pack("!H", 8 + len(payload)); udp[6:8] = b"\x00\x00"
    return bytes(eth) + bytes(ip) + bytes(udp) + payload


def fragments(eth, ip, udp, payload, mtu=1500, ident=0x4242):
    """IPv4 fragments of one UDP datagram (UDP checksum 0)."""
    udp = bytearray(udp[:8]); udp[4:6] = struct.pack("!H", 8 + len(payload)); udp[6:8] = b"\x00\x00"
    data = bytes(udp) + payload
    step = (mtu - 20) // 8 * 8
    out = []
    for off in range(0, len(data), step):
        chunk = data[off:off + step]
        h = bytearray(ip[:20]); h[0] = 0x45
        more = off + step < len(data)
        h[2:4] = struct.pack("!H", 20 + len(chunk)); h[4:6] = struct.pack("!H", ident)
        h[6:8] = struct.pack("!H", (0x2000 if more else 0) | (off // 8))
        h[10:12] = b"\x00\x00"; h[10:12] = struct.pack("!H", ip_csum(bytes(h)))
        out.append(bytes(eth) + bytes(h) + chunk)
    return out


def rtps_prefix(frame):
    i = frame.find(b"RTPS")
    return (i, frame[i + 8:i + 20]) if i >= 0 else (None, None)


def with_prefix(frame, new):
    i, old = rtps_prefix(frame)
    return frame.replace(old, new) if old else frame


def spool_counts(spool):
    c = collections.Counter()
    for sub in ("ready", "acked"):
        p = os.path.join(spool, sub)
        for n in os.listdir(p) if os.path.isdir(p) else []:
            try:
                f = json.loads(json.load(open(os.path.join(p, n)))["value"])
            except (FileNotFoundError, json.JSONDecodeError):
                continue
            c[f["ocsf"]["finding_info"]["analytic"]["uid"]] += 1
    return c


def diff(after, before):
    return {k: after[k] - before.get(k, 0) for k in after if after[k] - before.get(k, 0)}


def rss_kib(pid):
    for l in open(f"/proc/{pid}/status"):
        if l.startswith("VmRSS"):
            return int(l.split()[1])


def alive(pid):
    return os.path.exists(f"/proc/{pid}")
