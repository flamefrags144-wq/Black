SBOX = open('/home/user/Black/customvm/sbox.bin','rb').read()
P = 0x1000193
M = 0xFFFFFFFF
TARGET = 0x86d03165
def rol8(v, n=3): return ((v << n) | (v >> (8 - n))) & 0xFF
def run(key: bytes) -> int:
    assert len(key) == 32
    h, r3 = 0x811c9dc5, 0x42
    for i in range(0, 32, 2):
        x0, x1 = key[i], key[i+1]
        t1 = SBOX[x1 ^ rol8(r3)] ^ x0
        t2 = SBOX[t1 ^ r3 ^ i] ^ x1
        h = ((((t1 ^ h) * P) & M ^ ((t2 << 8) | i)) * P) & M
        r3 = t1 ^ t2
    return h
