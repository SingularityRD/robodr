def crc(words):
    c=0xFFFFFFFF; P=0x04c11db7
    for d in words:
        bit=1<<31
        for _ in range(32):
            if c & 0x80000000: c=((c<<1)&0xFFFFFFFF)^P
            else: c=(c<<1)&0xFFFFFFFF
            if d & bit: c^=P
            bit>>=1
    return c
print(hex(crc([0]*202)), hex(crc([0]*250)))
v=[((i*0x9E3779B9)&0xFFFFFFFF)^0xA5A50F0F for i in range(64)]
print(hex(crc(v[:16])), hex(crc(v)))
