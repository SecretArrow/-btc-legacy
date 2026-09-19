// tests/fuzz/fuzz_main.cpp
//
// Minimal deterministic fuzz driver. No libFuzzer — we generate
// malformed BDB/wallet byte streams from a small set of seeded
// mutators and feed each to the parsers. Any crash (segfault, UBSan
// report) is a finding.
//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>

extern int fuzz_bdb_parse(const std::vector<uint8_t>& data);
extern int fuzz_wallet_records(const std::vector<uint8_t>& data);
extern int fuzz_passphrase_verify(const std::vector<uint8_t>& data);

namespace {
std::vector<uint8_t> mutate(const std::vector<uint8_t>& base, uint64_t seed) {
    std::vector<uint8_t> out = base;
    // Simple PRNG: xoshiro256-ish
    uint64_t s = seed;
    auto next = [&]() -> uint64_t {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        return s;
    };
    size_t n_mutations = (next() % 5) + 1;
    for (size_t i = 0; i < n_mutations; ++i) {
        uint64_t op = next() % 4;
        if (op == 0 && !out.empty()) {
            // Flip a random byte
            size_t idx = next() % out.size();
            out[idx] ^= uint8_t(1u << (next() % 8));
        } else if (op == 1 && !out.empty()) {
            size_t idx = next() % out.size();
            out[idx] = uint8_t(next());
        } else if (op == 2 && !out.empty()) {
            // Truncate
            size_t newlen = next() % out.size();
            out.resize(newlen);
        } else {
            // Append a random byte
            out.push_back(uint8_t(next()));
        }
    }
    return out;
}

std::vector<uint8_t> base_bdb_file() {
    // Start from a minimal valid BDB hash file written by our writer
    // — but here we just synthesize a 4096-byte zero buffer with a
    // valid magic header.
    std::vector<uint8_t> b(4096, 0);
    // Magic = 0x00061561 (LE)
    b[12] = 0x61; b[13] = 0x15; b[14] = 0x06; b[15] = 0x00;
    // version = 9
    b[16] = 9; b[17] = 0; b[18] = 0; b[19] = 0;
    // pagesize = 4096
    b[20] = 0x00; b[21] = 0x10; b[22] = 0x00; b[23] = 0x00;
    // page_type = 8
    b[25] = 8;
    return b;
}

int run_iterations(int n) {
    int findings = 0;
    auto base = base_bdb_file();
    for (int i = 0; i < n; ++i) {
        auto mutated = mutate(base, uint64_t(i + 1));
        // Run all three fuzzers
        int rc;
        rc = fuzz_bdb_parse(mutated);
        rc += fuzz_wallet_records(mutated);
        rc += fuzz_passphrase_verify(mutated);
        if (rc != 0) {
            std::cerr << "FINDING at iteration " << i
                      << " (rc=" << rc << ")\n";
            ++findings;
        }
    }
    return findings;
}

} // namespace

int main(int argc, char** argv) {
    int n = 1000;
    if (argc > 1) n = std::atoi(argv[1]);
    if (n <= 0) n = 1000;
    std::cout << "Running " << n << " fuzz iterations...\n";
    int findings = run_iterations(n);
    if (findings == 0) {
        std::cout << "No findings.\n";
        return 0;
    }
    std::cerr << findings << " findings!\n";
    return 1;
}
