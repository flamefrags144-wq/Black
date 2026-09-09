#!/usr/bin/env python3
"""Auto re-solver for hyperstate-like instances with the SAME VM structure.
Usage: python3 solve_any.py <hyperstate_binary> [threads]
Extracts the CHECK target + S-box from the given binary, verifies the
bytecode matches the known VM program, compiles a tuned solver, runs it,
and verifies the winner on the given (pristine) binary.
"""
import re, subprocess, sys, os

KNOWN_CODE_HEX = open("/home/user/Black/customvm/code.bin", "rb").read().hex()

SOLVER_TPL = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
__SBOX__
#define P 0x01000193u
#define INIT 0x811c9dc5u
#define TARGET __TARGET__u
static const char CS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static atomic_int found = 0;
static char win[33];
static inline void block(uint32_t *h, uint8_t *r3, uint8_t x0, uint8_t x1, uint8_t i) {
    uint8_t r = *r3;
    uint8_t rol = (uint8_t)((r << 3) | (r >> 5));
    uint8_t t1 = SBOX[x1 ^ rol] ^ x0;
    uint8_t t2 = SBOX[(uint8_t)(t1 ^ r ^ i)] ^ x1;
    uint32_t hh = (t1 ^ *h) * P;
    hh = (hh ^ (((uint32_t)t2 << 8) | i)) * P;
    *h = hh;
    *r3 = (uint8_t)(t1 ^ t2);
}
static uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; *s = x; return x * 0x2545F4914F6CDD1Dull; }
static void *worker(void *arg) {
    long tid = (long)arg;
    uint64_t st = (uint64_t)time(0) * 0x9E3779B97F4A7C15ull + (uint64_t)tid * 0xBF58476D1CE4E5B9ull + 0x777;
    uint8_t pre[30];
    memcpy(pre, "IATCQ{", 6);
    while (!atomic_load(&found)) {
        for (int k = 6; k < 30; k++) pre[k] = (uint8_t)CS[xs(&st) % 62];
        uint32_t h = INIT; uint8_t r3 = 0x42;
        for (int i = 0; i < 30; i += 2) block(&h, &r3, pre[i], pre[i+1], (uint8_t)i);
        for (int bi = 0; bi < 62; bi++) {
            uint32_t hh = h; uint8_t rr = r3;
            block(&hh, &rr, (uint8_t)CS[bi], (uint8_t)'}', 30);
            if (hh == TARGET) {
                memcpy(win, pre, 30); win[30] = CS[bi]; win[31] = '}'; win[32] = 0;
                atomic_store(&found, 1);
                return NULL;
            }
        }
    }
    return NULL;
}
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 2;
    pthread_t *t = malloc(sizeof(pthread_t) * n);
    for (long i = 0; i < n; i++) pthread_create(&t[i], 0, worker, (void*)i);
    for (int i = 0; i < n; i++) pthread_join(t[i], 0);
    printf("FOUND: %s\n", win);
    return 0;
}
"""

def main():
    binary = sys.argv[1]
    threads = sys.argv[2] if len(sys.argv) > 2 else "2"
    d = open(binary, "rb").read()
    # 1. CHECK target: cmpl $imm32, 0x10(%rsp)  => 81 7c 24 10 <imm32>
    m = re.findall(rb"\x81\x7c\x24\x10(....)", d)
    assert len(m) == 1, f"expected 1 CHECK constant, found {len(m)}"
    target = int.from_bytes(m[0], "little")
    print(f"[*] CHECK target: 0x{target:08x}")
    # 2. LCG-decrypt blob at .rodata+0xC0 (file offset 0x20C0, 349 bytes)
    blob = d[0x20C0:0x20C0 + 349]
    assert len(blob) == 349
    st = 0xC0FFEE42
    out = bytearray()
    for b in blob:
        st = (st * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        out.append(b ^ ((st >> 16) & 0xFF))
    sbox, code = bytes(out[:256]), bytes(out[256:])
    # 3. structure check
    assert code.hex() == KNOWN_CODE_HEX, "bytecode DIFFERS from known VM program - manual analysis needed"
    assert len(set(sbox)) == 256, "sbox is not a permutation?!"
    print("[*] bytecode matches known VM program, sbox OK")
    # 4. build solver
    sdecl = ["static const unsigned char SBOX[256] = {"]
    for i in range(0, 256, 16):
        sdecl.append("    " + ", ".join("0x%02x" % b for b in sbox[i:i + 16]) + ("," if i < 240 else ""))
    sdecl.append("};")
    src = SOLVER_TPL.replace("__SBOX__", "\n".join(sdecl)).replace("__TARGET__", f"0x{target:08x}")
    work = "/tmp/autosolve"
    os.makedirs(work, exist_ok=True)
    open(f"{work}/solver_auto.c", "w").write(src)
    subprocess.run(["gcc", "-O2", "-pthread", "-o", f"{work}/solver_auto", f"{work}/solver_auto.c"], check=True)
    print("[*] solver built, running...")
    r = subprocess.run([f"{work}/solver_auto", threads], capture_output=True, text=True)
    print(r.stdout.strip())
    key = re.search(r"FOUND: (\S+)", r.stdout).group(1)
    # 5. verify on the given pristine binary
    v = subprocess.run([binary, key], capture_output=True, text=True)
    print("[*] binary says:", v.stdout.strip())
    assert "GRANTED" in v.stdout, "WINNER DID NOT GRANT?!"
    print(f"KEY: {key}")

if __name__ == "__main__":
    main()
