// btclegacy/crypto/key.h
#pragma once
//
// Bitcoin-compatible cryptographic key primitives, built on top of
// OpenSSL. The implementations mirror the historical Bitcoin Core
// src/key.{h,cpp} from the 2009-2015 era.
//
#include <cstdint>
#include <vector>
#include <string>

namespace btclegacy::crypto {

// Secp256k1-compatible operations, but we deliberately avoid pulling
// in libsecp256k1 here. Instead we delegate to OpenSSL's EC group
// (NID_secp256k1). OpenSSL supports this curve through the generic
// EC_KEY/EC_POINT API.
//
// For the legacy wallet tooling we need:
//   * Public key derivation from private key (priv→pub)
//   * Public key serialization (compressed 33-byte form and
//     uncompressed 65-byte form)
//   * HASH160(pubkey) → 20-byte Bitcoin address key id
//   * Base58check encoding of the address (P2PKH)
//   * WIF encoding of private keys
//
// (Because historical wallets may store *both* compressed and
// uncompressed public keys — the early-2009 wallets used uncompressed
// form until ~2012, after which Bitcoin Core switched to compressed.)

// Generate a cryptographically-secure random private key (32 bytes).
bool random_bytes(uint8_t* out, size_t n);

// Validate a private key (range 1..n-1 of secp256k1 order). Returns
// false for all-zero or out-of-range keys.
bool is_valid_privkey(const uint8_t privkey[32]);

// Derive a public key from a private key. Outputs the 33-byte
// compressed form by default, or 65-byte uncompressed form if requested.
bool privkey_to_pubkey(const uint8_t privkey[32],
                       bool compressed,
                       std::vector<uint8_t>& out_pub);

// hash160 = RIPEMD-160(SHA-256(x))
bool hash160(const std::vector<uint8_t>& data, uint8_t out[20]);

// Base58check encoding (used for Bitcoin addresses and WIF private keys).
std::string base58check_encode(const std::vector<uint8_t>& payload_with_version_byte);

// Encode a 20-byte P2PKH hash160 to a Base58check Bitcoin address.
// The version byte defaults to 0x00 (mainnet P2PKH).
std::string hash160_to_p2pkh_address(const uint8_t hash160[20], uint8_t version = 0x00);

// Encode a 32-byte private key + 1-byte pub key form to WIF.
// version: 0x80 mainnet, 0xEF testnet
// compressed: if true, append 0x01 before checksum
std::string privkey_to_wif(const uint8_t privkey[32], bool compressed, uint8_t version = 0x80);

// Decode a WIF string into (privkey, compressed).
bool wif_to_privkey(const std::string& wif, uint8_t out_privkey[32], bool& out_compressed);

} // namespace btclegacy::crypto
