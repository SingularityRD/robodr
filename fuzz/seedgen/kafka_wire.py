#!/usr/bin/env python3
"""Seed corpus of the `kafka_wire` fuzz target (std-lib only).

Writes one input per decoder / version class into the directory given as the
only argument (normally fuzz/corpus/kafka_wire): `selector || body`, the
selector as in fuzz/harness/kafka_wire.rs. The byte layouts mirror the
encoders of crates/robodr-export/src/kafka (proto.rs, batch.rs) and the
Kafka protocol guide; CRC-32C is checked against the "123456789" vector.

    python3 -I fuzz/seedgen/kafka_wire.py fuzz/corpus/kafka_wire
"""
import struct, sys, os
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
def i8(v): return struct.pack('>b', v)
def i16(v): return struct.pack('>h', v)
def i32(v): return struct.pack('>i', v)
def u32(v): return struct.pack('>I', v)
def i64(v): return struct.pack('>q', v)
def string(s): b=s.encode(); return i16(len(b))+b
def nstring(s): return i16(-1) if s is None else string(s)
def nbytes(b): return i32(-1) if b is None else i32(len(b))+b
def uvarint(v):
    o=b''
    while True:
        if v < 0x80: return o+bytes([v])
        o+=bytes([(v&0x7f)|0x80]); v >>= 7
def varint(v): return uvarint(((v<<1) ^ (v>>31)) & 0xffffffff)
def varlong(v): return uvarint(((v<<1) ^ (v>>63)) & 0xffffffffffffffff)
def varbytes(b): return varint(-1) if b is None else varint(len(b))+b
# CRC-32C (Castagnoli), reflected poly 0x82F63B78
T=[]
for n in range(256):
    c=n
    for _ in range(8): c = (c>>1) ^ 0x82F63B78 if c&1 else c>>1
    T.append(c)
def crc32c(d):
    c=0xffffffff
    for b in d: c = T[(c ^ b) & 0xff] ^ (c >> 8)
    return c ^ 0xffffffff
assert crc32c(b'123456789') == 0xE3069283

def api_versions():
    apis=[(0,3,9),(3,1,12),(18,0,3)]
    return i16(0)+i32(len(apis))+b''.join(i16(a)+i16(b)+i16(c) for a,b,c in apis)

def metadata(v):
    w=b''
    if v>=3: w+=i32(0)
    w+=i32(1)+i32(1)+string("broker-1.local")+i32(9092)+i16(-1)
    if v>=2: w+=i16(-1)
    w+=i32(1)
    w+=i32(1)+i16(0)+string("robodr.findings")+i8(0)+i32(2)
    for p in range(2):
        w+=i16(0)+i32(p)+i32(1)
        if v>=7: w+=i32(0)
        w+=i32(1)+i32(1)+i32(1)+i32(1)
        if v>=5: w+=i32(0)
    if v>=8: w+=i32(-2147483648)
    if v>=8: w+=i32(-2147483648)
    return w

def produce(v):
    w=i32(1)+string("robodr.findings")+i32(1)+i32(0)+i16(0)+i64(42)+i64(-1)
    if v>=5: w+=i64(0)
    if v>=8: w+=i32(1)+i32(0)+nstring("bad record")+nstring(None)
    return w+i32(0)

def record(i, ts_delta, key, value, headers):
    body=i8(0)+varlong(ts_delta)+varint(i)+varbytes(key)+varbytes(value)+varint(len(headers))
    for k,hv in headers: body+=varint(len(k))+k+varbytes(hv)
    return varint(len(body))+body

def batch(records, base_ts=1790000000000, pid=-1, epoch=-1, seq=-1):
    recs=b''.join(record(i, i*5, b'ugv-007', b'{"finding":%d}'%i, [(b'robodr-schema', b'2.0')]) for i in range(records))
    after_crc = i16(0)+i32(records-1)+i64(base_ts)+i64(base_ts+5*(records-1))+i64(pid)+i16(epoch)+i32(seq)+i32(records)+recs
    after_len = i32(-1)+i8(2)+u32(crc32c(after_crc))+after_crc
    return i64(0)+i32(len(after_len))+after_len

def req_header(api, ver, corr, client):
    return i16(api)+i16(ver)+i32(corr)+nstring(client)

seeds = {
 'seed-api-versions.bin': bytes([0])+api_versions(),
 'seed-metadata-v1.bin': bytes([1])+metadata(1),
 'seed-metadata-v8.bin': bytes([7*8+1])+metadata(8),
 'seed-metadata-v5.bin': bytes([4*8+1])+metadata(5),
 'seed-produce-v3.bin': bytes([2])+produce(3),
 'seed-produce-v8.bin': bytes([5*8+2])+produce(8),
 'seed-batch-crcfix.bin': bytes([3])+batch(2),
 'seed-batch-raw.bin': bytes([4])+batch(3)+batch(1),
 'seed-metadata-request.bin': bytes([5])+req_header(3,8,7,"robodr")+i32(1)+string("robodr.findings")+i8(0)+i8(0)+i8(0),
 'seed-produce-request.bin': bytes([6])+req_header(0,8,9,"robodr")+nstring(None)+i16(-1)+i32(30000)+i32(1)+string("robodr.findings")+i32(1)+i32(0)+nbytes(batch(2)),
 'seed-init-producer-id.bin': bytes([8])+i32(0)+i16(0)+i64(4242)+i16(0),
 'seed-init-producer-id-request.bin': bytes([5])+req_header(22,1,3,"robodr")+nstring(None)+i32(60000),
 'seed-batch-idempotent.bin': bytes([3])+batch(2, pid=4242, epoch=0, seq=7),
 'seed-primitives.bin': bytes([7])+string("abc")+nstring(None)+nbytes(b"xyz")+varint(-5)+varlong(1<<40)+varbytes(b"q")+i32(1)+b"\x01",
}
for n,b in seeds.items():
    open(os.path.join(out,n),'wb').write(b)
print(len(seeds),"seeds")
