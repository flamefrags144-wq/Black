#!/usr/bin/env python3
"""Test 32-byte IATCQ candidates against the exact VM accumulator."""
from pathlib import Path
import sys

binary = Path(__file__).parent / "unpacked" / "Custom VM" / "hyperstate" / "hyperstate4"
encrypted = binary.read_bytes()[0x20C0:0x21C0]
seed = 0xC0FFEE42
sbox = []
for item in encrypted:
    seed = (seed * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
    sbox.append(item ^ ((seed >> 16) & 0xFF))


def rol3(value: int) -> int:
    return ((value << 3) | (value >> 5)) & 0xFF


def vm_hash(flag: str) -> int:
    data = flag.encode("ascii")
    if len(data) != 32:
        raise ValueError(f"expected 32 ASCII bytes, got {len(data)}")
    h, previous = 0x811C9DC5, 0x42
    for i in range(0, 32, 2):
        a, b = data[i], data[i + 1]
        u = sbox[b ^ rol3(previous)] ^ a
        v = sbox[u ^ previous ^ i] ^ b
        h = ((h ^ u) * 0x01000193) & 0xFFFFFFFF
        h = ((h ^ ((v << 8) | i)) * 0x01000193) & 0xFFFFFFFF
        previous = u ^ v
    return h


for candidate in sys.argv[1:]:
    try:
        value = vm_hash(candidate)
        print(f"0x{value:08x} {'MATCH' if value == 0x86D03165 else 'no'}  {candidate}")
    except (UnicodeEncodeError, ValueError) as exc:
        print(f"invalid: {candidate!r}: {exc}")
