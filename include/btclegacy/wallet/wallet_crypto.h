// btclegacy/wallet/wallet_crypto.h
#pragma once
//
// Wallet-level cryptographic helpers, derived from the historical
// Bitcoin Core wallet encryption scheme (src/wallet/crypter.{h,cpp}).
//
// Bitcoin Core 0.4.0 introduced wallet encryption. The scheme is:
//
//   1) Generate a random 32-byte master key (CKeyingMaterial).
//   2) Generate a random 8-byte salt for passphrase-to-key derivation.
//   3) Derive a 32-byte AES key + 16-byte IV from the passphrase by
//      using OpenSSL's EVP_BytesToKey(EVP_sha512(), nullptr, salt,
//      passphrase, derive_count=25000 ...)  -- nDerivationMethod == 0.
//   4) Encrypt the 32-byte master key with AES-256-CBC using the
//      derived key/IV. Store the ciphertext as vchCryptedKey.
//   5) Per private key, encrypt the 32-byte secret with AES-256-CBC
//      using the *master* key and a fresh random 16-byte IV that is
//      prepended to the ciphertext. Store under "ckey" prefix.
//
// We deliberately do NOT invent a new scheme. We re-implement the
// historical scheme with OpenSSL.
//
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/platform/secure_memory.h"
#include <vector>
#include <string>
#include <cstdint>

namespace btclegacy::wallet {

// Verify a passphrase against the wallet's mkey records.
//
// Returns true on success (passphrase matches), false otherwise. If
// success, the derived master key is written into `derived_master_out`
// (cleared automatically by SecureBuffer on destruction).
//
// Strategy:
//   * Try each mkey record. For each, derive (key, IV) from the
//     passphrase and the salt and decrypt vchCryptedKey. If the AES
//     decrypt succeeds (PKCS7 padding checks out) and the resulting
//     master key is 32 bytes long, declare the passphrase correct.
//   * Cross-check: if any ckey record is present, additionally try
//     decrypting it with the master key and require a 32-byte output.
//
bool verify_passphrase(const ParsedWallet& w,
                       const std::string& passphrase,
                       platform::SecureBuffer& derived_master_out,
                       std::string& err);

// Decrypt a single ckey record using the supplied master key.
// Returns false if the AES-CBC decrypt fails (likely a wrong master key).
bool decrypt_ckey(const MasterKey& mk,
                  const platform::SecureBuffer& master,
                  const CryptedKeyRecord& ck,
                  platform::SecureBuffer& out_secret,
                  std::string& err);

// Build an mkey record from a passphrase (used by `create` to produce
// synthetic encrypted test wallets that verify correctly).
bool build_master_key_for_passphrase(const std::string& passphrase,
                                       MasterKey& out_mk,
                                       platform::SecureBuffer& out_master,
                                       uint32_t derive_count = 25000);

// Encrypt a private key (32 bytes) with the given master key. The
// 16-byte IV is stored as a prefix to the ciphertext (matches Bitcoin
// Core's ckey record layout).
bool encrypt_private_key(const platform::SecureBuffer& master,
                         const uint8_t privkey[32],
                         std::vector<uint8_t>& out_ciphertext,
                         std::string& err);

} // namespace btclegacy::wallet
