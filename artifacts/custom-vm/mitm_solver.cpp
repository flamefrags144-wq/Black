// Meet-in-the-middle solver for the last four 2-byte VM rounds.
// The VM keeps an 8-bit chaining state and a 32-bit FNV-style hash.
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

constexpr uint32_t P = 0x01000193u;
constexpr uint32_t TARGET = 0x86d03165u;
constexpr uint32_t CAPACITY_BITS = 25;
constexpr uint64_t CAPACITY = 1ull << CAPACITY_BITS;
constexpr uint64_t MASK = CAPACITY - 1;
constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
constexpr int N = sizeof(alphabet) - 1;

std::array<uint8_t, 256> sbox{};
std::vector<uint64_t> table(CAPACITY, 0);
std::atomic<bool> found{false};
std::string solution;
uint32_t pinv;

struct State { uint32_t h; uint8_t t; };

static uint8_t rol3(uint8_t x) { return uint8_t((x << 3) | (x >> 5)); }

static State forward(State in, uint8_t pos, uint8_t a, uint8_t b) {
    const uint8_t u = sbox[b ^ rol3(in.t)] ^ a;
    const uint8_t v = sbox[u ^ in.t ^ pos] ^ b;
    uint32_t h = (in.h ^ u) * P;
    h = (h ^ (uint32_t(v) << 8 | pos)) * P;
    return {h, uint8_t(u ^ v)};
}

static uint32_t inverse_hash(uint32_t after, uint8_t u, uint8_t v, uint8_t pos) {
    const uint32_t k = uint32_t(v) << 8 | pos;
    return ((after * pinv ^ k) * pinv) ^ u;
}

static uint64_t state_key(uint32_t h, uint8_t t) {
    return (uint64_t(t) << 32) | h;
}

static uint64_t index_for(uint64_t key) {
    // SplitMix64 finalizer; this keeps the open-addressing table evenly loaded.
    key += 0x9e3779b97f4a7c15ull;
    key = (key ^ (key >> 30)) * 0xbf58476d1ce4e5b9ull;
    key = (key ^ (key >> 27)) * 0x94d049bb133111ebull;
    return (key ^ (key >> 31)) & MASK;
}

static void insert(uint64_t key, uint32_t payload) {
    uint64_t item = (key << 24) | uint64_t(payload + 1); // zero remains an empty slot
    for (uint64_t slot = index_for(key);; slot = (slot + 1) & MASK) {
        if (table[slot] == 0) { table[slot] = item; return; }
        if ((table[slot] >> 24) == key) return; // one equivalent prefix is sufficient
    }
}

static bool lookup(uint64_t key, uint32_t &payload) {
    for (uint64_t slot = index_for(key);; slot = (slot + 1) & MASK) {
        uint64_t item = table[slot];
        if (item == 0) return false;
        if ((item >> 24) == key) {
            payload = uint32_t(item & 0xffffffu) - 1;
            return true;
        }
    }
}

static State prefix_state() {
    const std::string prefix = "IATCQ{vm_hash_collision_";
    State state{0x811c9dc5u, 0x42};
    for (int pos = 0; pos < 24; pos += 2)
        state = forward(state, uint8_t(pos), uint8_t(prefix[pos]), uint8_t(prefix[pos + 1]));
    return state;
}

static void build_forward_table(State initial) {
    // Positions 24..27: four regular flag characters, encoded in 24 payload bits.
    for (uint32_t a = 0; a < N; ++a)
        for (uint32_t b = 0; b < N; ++b)
            for (uint32_t c = 0; c < N; ++c)
                for (uint32_t d = 0; d < N; ++d) {
                    State one = forward(initial, 24, alphabet[a], alphabet[b]);
                    State two = forward(one, 26, alphabet[c], alphabet[d]);
                    const uint32_t payload = a | (b << 6) | (c << 12) | (d << 18);
                    insert(state_key(two.h, two.t), payload);
                }
}

static void search_backward(State /* initial */, int t_begin, int t_end) {
    // Positions 28,29,30 are free; position 31 is the required closing brace.
    for (int t28 = t_begin; t28 < t_end && !found.load(std::memory_order_relaxed); ++t28) {
        for (int c = 0; c < N && !found.load(std::memory_order_relaxed); ++c) {
            for (int d = 0; d < N && !found.load(std::memory_order_relaxed); ++d) {
                const uint8_t u28 = sbox[uint8_t(alphabet[d]) ^ rol3(uint8_t(t28))] ^ uint8_t(alphabet[c]);
                const uint8_t v28 = sbox[u28 ^ uint8_t(t28) ^ 28] ^ uint8_t(alphabet[d]);
                const uint8_t t30 = u28 ^ v28;
                for (int e = 0; e < N; ++e) {
                    const uint8_t u30 = sbox[uint8_t('}') ^ rol3(t30)] ^ uint8_t(alphabet[e]);
                    const uint8_t v30 = sbox[u30 ^ t30 ^ 30] ^ uint8_t('}');
                    const uint32_t h30 = inverse_hash(TARGET, u30, v30, 30);
                    const uint32_t h28 = inverse_hash(h30, u28, v28, 28);
                    uint32_t payload;
                    if (lookup(state_key(h28, uint8_t(t28)), payload)) {
                        int a = payload & 63, b = (payload >> 6) & 63;
                        int x = (payload >> 12) & 63, y = (payload >> 18) & 63;
                        std::string candidate = "IATCQ{vm_hash_collision_";
                        candidate += alphabet[a]; candidate += alphabet[b];
                        candidate += alphabet[x]; candidate += alphabet[y];
                        candidate += alphabet[c]; candidate += alphabet[d];
                        candidate += alphabet[e]; candidate += '}';
                        // Guard against a table/collision bookkeeping mistake.
                        State check = prefix_state();
                        for (int pos = 24; pos < 32; pos += 2)
                            check = forward(check, uint8_t(pos), uint8_t(candidate[pos]), uint8_t(candidate[pos+1]));
                        if (check.h == TARGET) {
                            if (!found.exchange(true)) solution = candidate;
                            return;
                        }
                    }
                }
            }
        }
    }
}

int main() {
    std::ifstream binary("unpacked/Custom VM/hyperstate/hyperstate4", std::ios::binary);
    if (!binary) { std::cerr << "Run from artifacts/custom-vm.\n"; return 2; }
    binary.seekg(0x20c0);
    std::array<uint8_t, 256> encrypted_sbox{};
    binary.read(reinterpret_cast<char *>(encrypted_sbox.data()), encrypted_sbox.size());
    if (!binary) { std::cerr << "Could not read encrypted S-box.\n"; return 2; }
    // setup_vm() decrypts the first 256 bytes into the lookup table at .bss+0x80.
    uint32_t seed = 0xc0ffee42u;
    for (size_t i = 0; i < sbox.size(); ++i) {
        seed = seed * 0x41c64e6du + 0x3039u;
        sbox[i] = encrypted_sbox[i] ^ uint8_t(seed >> 16);
    }

    // Newton iteration gives P^-1 modulo 2^32 for the odd FNV multiplier.
    pinv = 1;
    for (int i = 0; i < 5; ++i) pinv *= 2u - P * pinv;

    State initial = prefix_state();
    std::cout << "Prefix state: H=0x" << std::hex << initial.h << " T=0x" << int(initial.t)
              << std::dec << "\nBuilding " << uint64_t(N)*N*N*N << " forward states...\n";
    build_forward_table(initial);
    std::cout << "Searching backwards...\n";
    std::thread first(search_backward, initial, 0, 128);
    std::thread second(search_backward, initial, 128, 256);
    first.join(); second.join();
    if (!found) { std::cerr << "No preimage found (unexpected).\n"; return 1; }
    std::cout << solution << "\n";
    return 0;
}
