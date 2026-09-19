// src/wallet/wallet_crypto.cpp
//
// Higher-level wallet crypto: passphrase verification + ckey decryption,
// built directly on top of crypto::derive_key_from_passphrase and
// crypto::aes256cbc_decrypt.
//
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/crypto/encryption.h"
#include "btclegacy/crypto/key.h"
#include "btclegacy/util/strings.h"
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace btclegacy::wallet {

bool verify_passphrase(const ParsedWallet& w,
                       const std::string& passphrase,
                       platform::SecureBuffer& derived_master_out,
                       std::string& err) {
    derived_master_out.clear();
    if (!w.encrypted || w.master_keys.empty()) {
        err = "wallet is not encrypted";
        return false;
    }
    // Iterate each master key record. Bitcoin Core historically allowed
    // multiple mkey records to exist (for key rotation); each can decrypt
    // the corresponding ckey records.
    for (size_t i = 0; i < w.master_keys.size(); ++i) {
        const MasterKey& mk = w.master_keys[i];
        if (!mk.valid) continue;
        if (mk.nDerivationMethod != 0) {
            // We only support method 0 (EVP_BytesToKey SHA-512).
            continue;
        }
        platform::SecureBuffer key, iv;
        if (!crypto::derive_key_from_passphrase(passphrase, mk.vchSalt,
                                                 mk.nDeriveCount, key, iv)) {
            continue;
        }
        std::vector<uint8_t> plaintext;
        // Use strict PKCS7 padding — if the passphrase is wrong, the
        // padding check will fail with high probability.
        if (!crypto::aes256cbc_decrypt(key, iv, mk.vchCryptedKey, plaintext, true)) {
            // Padding error — likely wrong passphrase. Try next mkey.
            continue;
        }
        // The decrypted master key should be exactly 32 bytes long
        // (WALLET_CRYPTO_KEY_SIZE).
        if (plaintext.size() != crypto::WALLET_CRYPTO_KEY_SIZE) {
            // Length mismatch — wrong passphrase (very rare collision)
            continue;
        }
        // Cross-check: if the wallet has any ckey records, try to decrypt
        // one. If that also succeeds, we have very high confidence.
        if (!w.ckeys.empty()) {
            bool ckey_ok = false;
            for (const auto& ck : w.ckeys) {
                if (ck.vchCryptedSecret.size() < crypto::WALLET_CRYPTO_IV_SIZE)
                    continue;
                platform::SecureBuffer ck_key(plaintext.data(), plaintext.size());
                // First 16 bytes of ckey ciphertext are the IV (Bitcoin Core design).
                std::vector<uint8_t> iv2(ck.vchCryptedSecret.begin(),
                                         ck.vchCryptedSecret.begin() + crypto::WALLET_CRYPTO_IV_SIZE);
                std::vector<uint8_t> ct2(ck.vchCryptedSecret.begin() + crypto::WALLET_CRYPTO_IV_SIZE,
                                         ck.vchCryptedSecret.end());
                platform::SecureBuffer sb_iv2(iv2.data(), iv2.size());
                std::vector<uint8_t> pt;
                bool ok = crypto::aes256cbc_decrypt(ck_key, sb_iv2, ct2, pt, true);
                if (ok && pt.size() == 32) {
                    ckey_ok = true;
                    break;
                }
            }
            if (!ckey_ok) {
                // Got a master key that decrypts cleanly but doesn't
                // unlock ckeys — probably wrong passphrase with a
                // low-probability padding pass-through. Treat as wrong.
                continue;
            }
        }
        derived_master_out.resize(plaintext.size());
        std::memcpy(derived_master_out.data(), plaintext.data(), plaintext.size());
        // Wipe intermediate plaintext
        platform::secure_wipe(plaintext.data(), plaintext.size());
        return true;
    }
    err = "incorrect passphrase";
    return false;
}

bool decrypt_ckey(const MasterKey& mk,
                 const platform::SecureBuffer& master,
                 const CryptedKeyRecord& ck,
                 platform::SecureBuffer& out_secret,
                 std::string& err) {
    out_secret.clear();
    if (ck.vchCryptedSecret.size() < crypto::WALLET_CRYPTO_IV_SIZE) {
        err = "ckey too short";
        return false;
    }
    if (master.size() != crypto::WALLET_CRYPTO_KEY_SIZE) {
        err = "invalid master key size";
        return false;
    }
    std::vector<uint8_t> iv(ck.vchCryptedSecret.begin(),
                             ck.vchCryptedSecret.begin() + crypto::WALLET_CRYPTO_IV_SIZE);
    std::vector<uint8_t> ct(ck.vchCryptedSecret.begin() + crypto::WALLET_CRYPTO_IV_SIZE,
                             ck.vchCryptedSecret.end());
    platform::SecureBuffer sb_iv(iv.data(), iv.size());
    std::vector<uint8_t> pt;
    if (!crypto::aes256cbc_decrypt(master, sb_iv, ct, pt, true)) {
        err = "AES decrypt failed";
        return false;
    }
    if (pt.size() != 32) {
        err = "decrypted private key not 32 bytes";
        return false;
    }
    out_secret.resize(32);
    std::memcpy(out_secret.data(), pt.data(), 32);
    platform::secure_wipe(pt.data(), pt.size());
    return true;
}

bool build_master_key_for_passphrase(const std::string& passphrase,
                                       MasterKey& out_mk,
                                       platform::SecureBuffer& out_master,
                                       uint32_t derive_count) {
    out_mk = MasterKey{};
    out_master.clear();
    // Random 8-byte salt
    out_mk.vchSalt.resize(crypto::WALLET_CRYPTO_SALT_SIZE);
    if (RAND_bytes(out_mk.vchSalt.data(), crypto::WALLET_CRYPTO_SALT_SIZE) != 1) {
        return false;
    }
    // Random 32-byte master key
    out_master.resize(crypto::WALLET_CRYPTO_KEY_SIZE);
    if (RAND_bytes(out_master.data(), crypto::WALLET_CRYPTO_KEY_SIZE) != 1) {
        return false;
    }
    // Derive key + IV from passphrase
    platform::SecureBuffer key, iv;
    if (!crypto::derive_key_from_passphrase(passphrase, out_mk.vchSalt,
                                              derive_count, key, iv)) {
        return false;
    }
    // Encrypt master key
    std::vector<uint8_t> plain(out_master.data(), out_master.data() + out_master.size());
    std::vector<uint8_t> ct;
    if (!crypto::aes256cbc_encrypt(key, iv, plain, ct)) {
        return false;
    }
    out_mk.vchCryptedKey = std::move(ct);
    out_mk.nDerivationMethod = 0;
    out_mk.nDeriveCount = derive_count;
    out_mk.valid = true;
    return true;
}

bool encrypt_private_key(const platform::SecureBuffer& master,
                         const uint8_t privkey[32],
                         std::vector<uint8_t>& out_ciphertext,
                         std::string& err) {
    if (master.size() != crypto::WALLET_CRYPTO_KEY_SIZE) {
        err = "master key wrong size";
        return false;
    }
    // Fresh random IV
    uint8_t iv_bytes[crypto::WALLET_CRYPTO_IV_SIZE];
    if (RAND_bytes(iv_bytes, sizeof(iv_bytes)) != 1) {
        err = "RAND_bytes failed";
        return false;
    }
    platform::SecureBuffer iv(iv_bytes, sizeof(iv_bytes));
    platform::secure_wipe(iv_bytes, sizeof(iv_bytes));
    std::vector<uint8_t> plain(privkey, privkey + 32);
    std::vector<uint8_t> ct;
    if (!crypto::aes256cbc_encrypt(master, iv, plain, ct)) {
        err = "AES encrypt failed";
        return false;
    }
    // Prepend IV to ciphertext — matches Bitcoin Core's "ckey" record layout
    out_ciphertext.clear();
    out_ciphertext.insert(out_ciphertext.end(), iv.data(), iv.data() + iv.size());
    out_ciphertext.insert(out_ciphertext.end(), ct.begin(), ct.end());
    platform::secure_wipe(plain.data(), plain.size());
    return true;
}

} // namespace btclegacy::wallet
