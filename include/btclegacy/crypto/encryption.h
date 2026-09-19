// btclegacy/crypto/encryption.h
#pragma once
//
// Low-level AES-256-CBC + passphrase-to-key derivation, mirroring
// Bitcoin Core's CCrypter (src/wallet/crypter.{h,cpp}).
//
#include "btclegacy/platform/secure_memory.h"
#include <vector>
#include <cstdint>
#include <string>

namespace btclegacy::crypto {

constexpr uint32_t WALLET_CRYPTO_KEY_SIZE = 32;
constexpr uint32_t WALLET_CRYPTO_SALT_SIZE = 8;
constexpr uint32_t WALLET_CRYPTO_IV_SIZE = 16;

// Derive key+IV from a passphrase using EVP_BytesToKey(EVP_sha512()).
// This is the historical Bitcoin Core nDerivationMethod == 0 path.
bool derive_key_from_passphrase(const std::string& passphrase,
                                 const std::vector<uint8_t>& salt,
                                 uint32_t rounds,
                                 platform::SecureBuffer& out_key,
                                 platform::SecureBuffer& out_iv);

// AES-256-CBC encrypt plaintext (with PKCS7 padding).
bool aes256cbc_encrypt(const platform::SecureBuffer& key,
                       const platform::SecureBuffer& iv,
                       const std::vector<uint8_t>& plaintext,
                       std::vector<uint8_t>& out_ciphertext);

// AES-256-CBC decrypt ciphertext. Returns false if the padding check
// fails (which is the signal we use to detect an incorrect passphrase
// when decrypting the master key).
bool aes256cbc_decrypt(const platform::SecureBuffer& key,
                       const platform::SecureBuffer& iv,
                       const std::vector<uint8_t>& ciphertext,
                       std::vector<uint8_t>& out_plaintext,
                       bool strict_padding = true);

// Constant-time comparison
bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t n);

} // namespace btclegacy::crypto
