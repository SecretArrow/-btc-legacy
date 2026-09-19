// src/crypto/key.cpp
//
// Bitcoin-compatible key primitives, built on OpenSSL's NID_secp256k1
// generic EC API. We avoid pulling in libsecp256k1 here — OpenSSL supports
// secp256k1 through EC_KEY/EC_POINT, which is sufficient for legacy
// wallet inspection and synthetic test-key generation.
//
// References: Bitcoin Core src/key.{h,cpp} (2009-2015 era).
//
#include "btclegacy/crypto/key.h"
#include "btclegacy/util/strings.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <cstring>
#include <memory>
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace btclegacy::crypto {

namespace {

struct EcCtxDeleter {
    void operator()(EC_KEY* k) const { if (k) EC_KEY_free(k); }
};
struct EcGroupDeleter {
    void operator()(EC_GROUP* g) const { if (g) EC_GROUP_free(g); }
};
struct EcPointDeleter {
    void operator()(EC_POINT* p) const { if (p) EC_POINT_free(p); }
};
struct BnDeleter {
    void operator()(BIGNUM* b) const { if (b) BN_free(b); }
};

// secp256k1 curve parameter N (group order):
//   0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// Private keys must be in [1, N-1].
class Secp256k1 {
public:
    Secp256k1() {
        ctx_ = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!ctx_) throw std::runtime_error("EC_KEY_new failed");
        group_ = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group_) throw std::runtime_error("EC_GROUP_new failed");
        // Capture N as BIGNUM
        BN_CTX* bn = BN_CTX_new();
        order_ = BN_new();
        EC_GROUP_get_order(group_, order_, bn);
        BN_CTX_free(bn);
    }
    ~Secp256k1() {
        if (order_) BN_free(order_);
        if (group_) EC_GROUP_free(group_);
        if (ctx_) EC_KEY_free(ctx_);
    }
    bool valid_priv(const uint8_t priv[32]) {
        std::unique_ptr<BIGNUM, BnDeleter> s(BN_bin2bn(priv, 32, nullptr));
        if (!s) return false;
        if (BN_is_zero(s.get())) return false;
        // s >= 1 and s < N
        return (BN_cmp(s.get(), order_) < 0);
    }
    bool pubkey(const uint8_t priv[32], bool compressed,
                std::vector<uint8_t>& out_pub) {
        std::unique_ptr<BIGNUM, BnDeleter> s(BN_bin2bn(priv, 32, nullptr));
        if (!s) return false;
        if (BN_is_zero(s.get())) return false;
        if (BN_cmp(s.get(), order_) >= 0) return false;
        // Create a fresh EC_KEY for this derivation (thread-safety)
        EC_KEY* eck = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!eck) return false;
        bool ok = (EC_KEY_set_private_key(eck, s.get()) == 1);
        if (ok) {
            EC_POINT* pub = EC_POINT_new(group_);
            if (pub && EC_POINT_mul(group_, pub, s.get(), nullptr, nullptr, nullptr) == 1) {
                ok = (EC_KEY_set_public_key(eck, pub) == 1);
                if (ok) {
                    // Serialize
                    if (compressed) {
                        size_t need = 33;
                        std::vector<uint8_t> buf(need, 0);
                        size_t written = EC_POINT_point2oct(group_, pub,
                            POINT_CONVERSION_COMPRESSED, buf.data(), need, nullptr);
                        if (written == need) out_pub.assign(buf.begin(), buf.end());
                        else ok = false;
                    } else {
                        size_t need = 65;
                        std::vector<uint8_t> buf(need, 0);
                        size_t written = EC_POINT_point2oct(group_, pub,
                            POINT_CONVERSION_UNCOMPRESSED, buf.data(), need, nullptr);
                        if (written == need) out_pub.assign(buf.begin(), buf.end());
                        else ok = false;
                    }
                }
                EC_POINT_free(pub);
            } else ok = false;
        }
        EC_KEY_free(eck);
        return ok;
    }
private:
    EC_KEY*  ctx_ = nullptr;
    EC_GROUP* group_ = nullptr;
    BIGNUM*  order_ = nullptr;
};

Secp256k1& secp() {
    static Secp256k1 instance;
    return instance;
}

// Base58 alphabet (Bitcoin Core)
const char* base58_alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::vector<uint8_t> base58_encode_raw(const std::vector<uint8_t>& input) {
    // Convert big-endian bytes to big-endian base58 representation.
    std::vector<uint8_t> digits;
    digits.push_back(0);
    for (uint8_t byte : input) {
        int carry = byte;
        for (size_t i = 0; i < digits.size(); ++i) {
            carry += int(digits[i]) * 256;
            digits[i] = uint8_t(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(uint8_t(carry % 58));
            carry /= 58;
        }
    }
    // Preserve leading zero bytes as leading '1' characters.
    size_t leading_zeros = 0;
    for (uint8_t b : input) {
        if (b == 0) leading_zeros++;
        else break;
    }
    std::vector<uint8_t> out;
    for (size_t i = 0; i < leading_zeros; ++i) out.push_back(0); // '1'
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        out.push_back(*it);
    }
    return out;
}

} // namespace

bool random_bytes(uint8_t* out, size_t n) {
    return RAND_bytes(out, int(n)) == 1;
}

bool is_valid_privkey(const uint8_t privkey[32]) {
    try {
        return secp().valid_priv(privkey);
    } catch (...) {
        return false;
    }
}

bool privkey_to_pubkey(const uint8_t privkey[32],
                       bool compressed,
                       std::vector<uint8_t>& out_pub) {
    try {
        return secp().pubkey(privkey, compressed, out_pub);
    } catch (...) {
        return false;
    }
}

bool hash160(const std::vector<uint8_t>& data, uint8_t out[20]) {
    uint8_t sha[32];
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) return false;
    bool ok = (EVP_DigestInit_ex(md, EVP_sha256(), nullptr) == 1 &&
               EVP_DigestUpdate(md, data.data(), data.size()) == 1 &&
               EVP_DigestFinal_ex(md, sha, nullptr) == 1);
    EVP_MD_CTX_free(md);
    if (!ok) return false;

    md = EVP_MD_CTX_new();
    if (!md) return false;
    unsigned int ripemd_len = 20;
    ok = (EVP_DigestInit_ex(md, EVP_ripemd160(), nullptr) == 1 &&
          EVP_DigestUpdate(md, sha, 32) == 1 &&
          EVP_DigestFinal_ex(md, out, &ripemd_len) == 1);
    EVP_MD_CTX_free(md);
    return ok && ripemd_len == 20;
}

std::string base58check_encode(const std::vector<uint8_t>& payload) {
    // payload already includes the version byte (1 prefix byte)
    uint8_t sha1[32], sha2[32];
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) return "";
    if (EVP_DigestInit_ex(md, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(md, payload.data(), payload.size()) != 1 ||
        EVP_DigestFinal_ex(md, sha1, nullptr) != 1) {
        EVP_MD_CTX_free(md); return "";
    }
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (!md) return "";
    if (EVP_DigestInit_ex(md, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(md, sha1, 32) != 1 ||
        EVP_DigestFinal_ex(md, sha2, nullptr) != 1) {
        EVP_MD_CTX_free(md); return "";
    }
    EVP_MD_CTX_free(md);

    // Append first 4 bytes of sha2 as checksum
    std::vector<uint8_t> full(payload.begin(), payload.end());
    full.insert(full.end(), sha2, sha2 + 4);

    auto encoded = base58_encode_raw(full);
    std::string out; out.reserve(encoded.size());
    for (uint8_t v : encoded) out.push_back(base58_alphabet[v]);
    return out;
}

std::string hash160_to_p2pkh_address(const uint8_t hash160[20], uint8_t version) {
    std::vector<uint8_t> payload;
    payload.push_back(version);
    payload.insert(payload.end(), hash160, hash160 + 20);
    return base58check_encode(payload);
}

std::string privkey_to_wif(const uint8_t privkey[32], bool compressed, uint8_t version) {
    std::vector<uint8_t> payload;
    payload.push_back(version);
    payload.insert(payload.end(), privkey, privkey + 32);
    if (compressed) payload.push_back(0x01);
    return base58check_encode(payload);
}

bool wif_to_privkey(const std::string& wif, uint8_t out_privkey[32], bool& out_compressed) {
    // Decode Base58
    std::vector<int> digits;
    std::vector<uint8_t> bytes;
    // Count leading '1's
    size_t leading = 0;
    for (char c : wif) {
        if (c == '1') leading++;
        else break;
    }
    // Convert to base 256
    bytes.push_back(0);
    for (char c : wif) {
        const char* p = strchr(base58_alphabet, c);
        if (!p) return false;
        int carry = int(p - base58_alphabet);
        for (size_t i = 0; i < bytes.size(); ++i) {
            carry += int(bytes[i]) * 58;
            bytes[i] = uint8_t(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) { bytes.push_back(uint8_t(carry & 0xff)); carry >>= 8; }
    }
    // Reverse bytes
    std::reverse(bytes.begin(), bytes.end());
    // Strip the leading zero bytes (encoded as '1')
    // The original input had `leading` leading '1's which encoded to `leading` zero bytes.
    if (bytes.size() < leading) return false;
    bytes.erase(bytes.begin(), bytes.begin() + leading);
    // Now bytes should be: version(1) + privkey(32) [+ 0x01] + checksum(4)
    if (bytes.size() < 1 + 32 + 4) return false;
    out_compressed = (bytes.size() == 1 + 32 + 1 + 4);
    if (out_compressed && bytes[33] != 0x01) return false;
    std::memcpy(out_privkey, bytes.data() + 1, 32);
    return true;
}

} // namespace btclegacy::crypto
