d = open('extracted/Custom VM/hyperstate/hyperstate4','rb').read()
blob = d[0x20c0:0x20c0+349]
assert len(blob) == 349
state = 0xc0ffee42
out = bytearray()
for b in blob:
    state = (state * 0x41c64e6d + 0x3039) & 0xFFFFFFFF
    out.append(b ^ ((state >> 16) & 0xFF))
open('sbox.bin','wb').write(bytes(out[:256]))
open('code.bin','wb').write(bytes(out[256:]))
print('decrypted: sbox 256B, code', len(out[256:]), 'B')
