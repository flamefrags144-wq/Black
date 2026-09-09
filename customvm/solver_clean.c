#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include "sbox.h"
#define P 0x01000193u
#define INIT 0x811c9dc5u
#define TARGET 0x86d03165u
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
    uint64_t st = (uint64_t)time(0) * 0x9E3779B97F4A7C15ull + (uint64_t)tid * 0xBF58476D1CE4E5B9ull + 0x12345;
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
