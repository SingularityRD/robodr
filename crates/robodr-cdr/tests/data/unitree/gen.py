import struct, random, json, sys
random.seed(7)
exec(open('crc.py').read().split('print(')[0])

# ---- independent CDR writer
class W:
    def __init__(s, be=False, v2=False):
        s.b=bytearray(); s.e='>' if be else '<'; s.v2=v2
    def al(s,n):
        n=min(n,4 if s.v2 else 8)
        while len(s.b)%n: s.b.append(0)
    def p(s,fmt,v):
        n=struct.calcsize(fmt); s.al(n); s.b+=struct.pack(s.e+fmt,v)
# schema: list of (type, count) ; type str primitive or list (struct)
P={'u8':'B','i8':'b','u16':'H','i16':'h','u32':'I','i32':'i','f32':'f'}
def gen(t):
    if t in('u8',): return random.randrange(256)
    if t=='i8': return random.randrange(-128,128)
    if t=='u16': return random.randrange(65536)
    if t=='i16': return random.randrange(-32768,32768)
    if t in('u32',): return random.randrange(2**32)
    if t=='i32': return random.randrange(-2**31,2**31)
    if t=='f32': return struct.unpack('<f',struct.pack('<f',random.uniform(-100,100)))[0]
def mk(schema):
    out=[]
    for t,n in schema:
        vals=[]
        for _ in range(n):
            vals.append(mk(t) if isinstance(t,list) else gen(t))
        out.append(vals)
    return out
def ser(w,schema,val):
    for (t,n),vals in zip(schema,val):
        if isinstance(t,list):
            if w.v2 and n>1:
                w.al(4); pos=len(w.b); w.b+=b'\0\0\0\0'
                for v in vals: ser(w,t,v)
                struct.pack_into(w.e+'I',w.b,pos,len(w.b)-pos-4)
            else:
                for v in vals: ser(w,t,v)
        else:
            for v in vals: w.p(P[t],v)
# C++ natural layout image (independent)
def size_align(schema):
    off=0; mal=1
    for t,n in schema:
        if isinstance(t,list): s,a=size_align(t)
        else: s=a=struct.calcsize(P[t])
        off=(off+a-1)//a*a + s*n; mal=max(mal,a)
    return (off+mal-1)//mal*mal, mal
def img(buf,schema,val):
    base=len(buf); _,mal=size_align(schema)
    for (t,n),vals in zip(schema,val):
        if isinstance(t,list):
            s,a=size_align(t)
            while (len(buf)-base)%a: buf.append(0)
            for v in vals:
                st=len(buf); img(buf,t,v)
        else:
            a=struct.calcsize(P[t])
            while (len(buf)-base)%a: buf.append(0)
            for v in vals: buf+=struct.pack('<'+P[t],v)
    while (len(buf)-base)%mal: buf.append(0)
def crc_of(schema,val):
    b=bytearray(); img(b,schema,val)
    words=[struct.unpack_from('<I',b,i*4)[0] for i in range(len(b)//4-1)]
    return len(b), crc(words)

GoMotorCmd=[('u8',1),('f32',5),('u32',3)]
GoLowCmd=[('u8',2),('u8',1),('u8',1),('u32',2),('u32',2),('u16',1),(GoMotorCmd,20),([('u8',1),('u8',3)],1),('u8',40),('u8',12),('u8',2),('u8',1),('u32',1),('u32',1)]
Imu8=[('f32',4),('f32',3),('f32',3),('f32',3),('i8',1)]
GoMotorState=[('u8',1),('f32',7),('i8',1),('u32',1),('u32',2)]
GoBms=[('u8',4),('i32',1),('u16',1),('i8',2),('i8',2),('u16',15)]
GoLowState=[('u8',2),('u8',1),('u8',1),('u32',2),('u32',2),('u16',1),(Imu8,1),(GoMotorState,20),(GoBms,1),('i16',4),('i16',4),('u32',1),('u8',40),('u8',1),('f32',1),('i8',1),('i8',1),('f32',1),('f32',1),('u16',4),('u32',1),('u32',1)]
HgMotorCmd=[('u8',1),('f32',5),('u32',1)]
HgLowCmd=[('u8',1),('u8',1),(HgMotorCmd,35),('u32',4),('u32',1)]
Imu16=[('f32',4),('f32',3),('f32',3),('f32',3),('i16',1)]
HgMotorState=[('u8',1),('f32',4),('i16',2),('f32',1),('u32',2),('u32',1),('u32',4)]
HgLowState=[('u32',2),('u8',1),('u8',1),('u32',1),(Imu16,1),(HgMotorState,35),('u8',40),('u32',4),('u32',1)]

def setcrc(schema,val):
    n,c=crc_of(schema,val); val[-1]=[c]; return n,c
out={}
for name,sch in [('golowcmd',GoLowCmd),('golowstate',GoLowState),('hglowcmd',HgLowCmd),('hglowstate',HgLowState)]:
    v=mk(sch); n,c=setcrc(sch,v)
    for tag,be,v2,hdr in [('le',False,False,b'\x00\x01\x00\x00'),('be',True,False,b'\x00\x00\x00\x00'),('x2',False,True,b'\x00\x07\x00\x00')]:
        w=W(be,v2); ser(w,sch,v)
        open(f'{name}_{tag}.bin','wb').write(hdr+bytes(w.b))
        print(name,tag,'body',len(w.b),'imgsize',n,'crc',hex(c))
    json.dump(v,open(f'{name}.json','w'))
