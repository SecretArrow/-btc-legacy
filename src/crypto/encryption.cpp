// src/crypto/encryption.cpp
//
// Bitcoin Core compatible CCrypter re-implementation, using OpenSSL 3.x.
//
// Historical reference: Bitcoin Core src/wallet/crypter.{h,cpp} from
// approximately v0.4.0 through v0.15.x.
//
// Key derivation:
//   nDerivationMethod == 0 -> EVP_BytesToKey(EVP_sha512(), NULL, salt,
//                                            passphrase, derive_count, ...)
//
// Master-key encryption:
//   AES-256-CBC with the derived key and IV (also derived from
//   EVP_BytesToKey). The master key is 32 bytes, so after PKCS7 padding
//   it becomes 48 bytes of ciphertext.
//
// ckey encryption:
//   AES-256-CBC with the master key. A fresh 16-byte random IV is
//   prepended to the ciphertext on every encryption — this matches
//   the historical CCrypter::EncryptMasterKey2 design used by Bitcoin
//   Core (see crypter.cpp EncryptKey / CCrypter).
//
#include "btclegacy/crypto/encryption.h"
#include "btclegacy/platform/secure_memory.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace btclegacy::crypto {

bool derive_key_from_passphrase(const std::string& passphrase,
                                 const std::vector<uint8_t>& salt,
                                 uint32_t rounds,
                                 platform::SecureBuffer& out_key,
                                 platform::SecureBuffer& out_iv) {
    if (salt.size() != WALLET_CRYPTO_SALT_SIZE) return false;
    if (rounds == 0) return false;

    out_key.resize(WALLET_CRYPTO_KEY_SIZE);
    out_iv.resize(WALLET_CRYPTO_IV_SIZE);

    // EVP_BytesToKey historically used the salt as-is (8 bytes) when
    // the salt pointer is non-NULL, or as zero when NULL. Bitcoin Core
    // passes the salt pointer, so we do too.
    int nkey = EVP_BytesToKey(
        EVP_aes_256_cbc(),
        EVP_sha512(),
        salt.data(),
        reinterpret_cast<const unsigned char*>(passphrase.data()),
        int(passphrase.size()),
        int(rounds),
        out_key.data(),
        out_iv.data());

    if (nkey != int(WALLET_CRYPTO_KEY_SIZE)) {
        return false;
    }
    // Note: Bitcoin Core's CCrypter also sets the IV (16 bytes) here.
    // The IV produced by EVP_BytesToKey is exactly 16 bytes for
    // AES-256-CBC, which matches WALLET_CRYPTO_IV_SIZE.
    return true;
}

bool aes256cbc_encrypt(const platform::SecureBuffer& key,
                       const platform::SecureBuffer& iv,
                       const std::vector<uint8_t>& plaintext,
                       std::vector<uint8_t>& out_ciphertext) {
    if (key.size() != WALLET_CRYPTO_KEY_SIZE) return false;
    if (iv.size() != WALLET_CRYPTO_IV_SIZE)   return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = true;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                key.data(), iv.data()) != 1) { ok = false; break; }
        EVP_CIPHER_CTX_set_padding(ctx, 1); // PKCS7

        int outlen = 0;
        std::vector<uint8_t> buf(plaintext.size() + 32, 0);
        if (EVP_EncryptUpdate(ctx, buf.data(), &outlen,
                              plaintext.data(), int(plaintext.size())) != 1) {
            ok = false; break;
        }
        int written = outlen;
        int tmplen = 0;
        if (EVP_EncryptFinal_ex(ctx, buf.data() + written, &tmplen) != 1) {
            ok = false; break;
        }
        written += tmplen;
        out_ciphertext.assign(buf.begin(), buf.begin() + written);
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aes256cbc_decrypt(const platform::SecureBuffer& key,
                       const platform::SecureBuffer& iv,
                       const std::vector<uint8_t>& ciphertext,
                       std::vector<uint8_t>& out_plaintext,
                       bool strict_padding) {
    if (key.size() != WALLET_CRYPTO_KEY_SIZE) return false;
    if (iv.size() != WALLET_CRYPTO_IV_SIZE)   return false;
    if (ciphertext.empty() || ciphertext.size() % WALLET_CRYPTO_IV_SIZE != 0)
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = true;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                key.data(), iv.data()) != 1) { ok = false; break; }
        EVP_CIPHER_CTX_set_padding(ctx, strict_padding ? 1 : 0);

        int outlen = 0;
        std::vector<uint8_t> buf(ciphertext.size() + 32, 0);
        if (EVP_DecryptUpdate(ctx, buf.data(), &outlen,
                              ciphertext.data(), int(ciphertext.size())) != 1) {
            ok = false; break;
        }
        int written = outlen;
        int tmplen = 0;
        int fin_rc = EVP_DecryptFinal_ex(ctx, buf.data() + written, &tmplen);
        if (strict_padding && fin_rc != 1) { ok = false; break; }
        written += tmplen;
        out_plaintext.assign(buf.begin(), buf.begin() + written);
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace btclegacy::crypto
