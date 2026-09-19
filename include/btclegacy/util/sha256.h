// btclegacy/util/sha256.h
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
namespace btclegacy::util {

/// Standalone SHA-256 implementation (no OpenSSL dependency for the hash itself,
/// but the project also uses OpenSSL's EVP_* API for key derivation).
struct Sha256 {
    Sha256();
    void update(const uint8_t* data, size_t len);
    void update(const std::string& s);
    void update(const std::vector<uint8_t>& v);
    void finish(uint8_t out[32]);
    void reset();
private:
    uint32_t h_[8];
    uint64_t total_;
    uint8_t buf_[64];
    size_t buflen_;
};

std::string sha256_hex(const uint8_t* data, size_t len);
std::string sha256_hex_file(const std::string& path);

} // namespace btclegacy::util
