import subprocess, sys
sys.path.insert(0, "/home/user/Black/customvm")
from emu import run
V = [b"A"*32, b"B"*32, bytes(range(1,33)), b"IATCQ{"+b"X"*25+b"}", b"0"*32]
ok = 0
for i, k in enumerate(V, 1):
    p = subprocess.run(["/home/user/Black/customvm/hs_patched", k], capture_output=True)
    real = int.from_bytes(p.stdout[:4], "little")
    emu = run(k)
    ok += (real == emu)
    print(f"vec{i}  real={real:08x}  emu={emu:08x}  {'MATCH' if real==emu else 'FAIL'}")
print(f"{ok}/{len(V)} test vectors identical")
