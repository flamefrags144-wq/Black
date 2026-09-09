# Custom VM (hyperstate4) — solution
Binary SHA-256: `0f722ac3e1cfb1b9781bc4aea871f5ee33fa5c19c8ae9b062956a93a4040a23f`

## Verified keys (all print `[+] ACCESS GRANTED` on pristine binary)
- `IATCQ{AgfnTbPXu50XcVQs0ue8uRL6c}` (primary)
- `IATCQ{U1dkpoK7vgFn2ZoP92jS0EBHd}` (spare)
- `IATCQ{hqHcHkS166sxChIfVOX6tW2CE}` (spare)

## Verify
./extracted/Custom\ VM/hyperstate/hyperstate4 'IATCQ{AgfnTbPXu50XcVQs0ue8uRL6c}'
python3 verify_emu.py   # emulator vs real binary: 5/5 MATCH

## Files
- `Custom+VM.zip`, `extracted/` — challenge as received
- `decrypt.py` — LCG decrypt -> sbox.bin (AES S-box) + code.bin (93B VM bytecode)
- `emu.py` — bit-exact VM model; `verify_emu.py` — differential test
- `hs_patched` — instrumented copy leaking internal hash (analysis only)
- `solver_clean.c` — format-constrained preimage search (needs TARGET+sbox per instance)
- `solve_any.py` — auto re-solver: give it a same-structure binary, get a key
