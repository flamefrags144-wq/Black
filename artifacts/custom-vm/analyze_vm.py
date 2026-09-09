#!/usr/bin/env python3
from pathlib import Path
p = Path(__file__).parent / 'unpacked' / 'Custom VM' / 'hyperstate' / 'hyperstate4'
data=p.read_bytes()
enc=data[0x20c0:0x20c0+0x15d]
seed=0xc0ffee42
code=[]
for byte in enc:
    seed=(seed*0x41c64e6d+0x3039)&0xffffffff
    code.append(((seed>>16)&0xff)^byte)
print(f'Encrypted VM material: {len(enc)} bytes')
print('First 0x100 decoded bytes:')
for off in range(0,len(code),16):
    hx=' '.join(f'{x:02x}' for x in code[off:off+16])
    asc=''.join(chr(x) if 32<=x<127 else '.' for x in code[off:off+16])
    print(f'{off:03x}: {hx:<47}  {asc}')
