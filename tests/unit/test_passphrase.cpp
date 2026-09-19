// tests/unit/test_passphrase.cpp
//
// Generate a synthetic encrypted wallet, then verify the passphrase
// using the wallet_crypto::verify_passphrase function — which is
// the actual CCrypter-equivalent algorithm.
//
#include "test_macros.h"
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/parser/serializer.h"
#include "btclegacy/bdb/bdb_writer.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/platform/secure_memory.h"
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>

using namespace btclegacy::wallet;
using namespace btclegacy::bdb;
using namespace btclegacy::platform;
using namespace btclegacy::parser;

static WriteRecord make_mkey_record(const MasterKey& mk) {
    WriteRecord wr;
    wr.key = std::vector<uint8_t>(PREFIX_MKEY, PREFIX_MKEY + std::strlen(PREFIX_MKEY));
    wr.key.push_back(0); wr.key.push_back(0); wr.key.push_back(0); wr.key.push_back(1);
    Serializer s;
    s.put_bytes_prefixed(mk.vchCryptedKey);
    s.put_bytes_prefixed(mk.vchSalt);
    s.put_u32(mk.nDerivationMethod);
    s.put_u32(mk.nDeriveCount);
    wr.value = s.take();
    return wr;
}

TEST(passphrase_build_master_key) {
    MasterKey mk;
    SecureBuffer master;
    EXPECT(build_master_key_for_passphrase("test-password", mk, master, 1000));
    EXPECT(mk.valid);
    EXPECT(mk.vchSalt.size() == 8);
    EXPECT(mk.vchCryptedKey.size() == 48); // 32-byte key + 16-byte PKCS7 padding
    EXPECT(mk.nDerivationMethod == 0);
    EXPECT(mk.nDeriveCount == 1000);
    EXPECT(master.size() == 32);
}

TEST(passphrase_verify_correct) {
    // Build a master key from "correct horse battery staple"
    MasterKey mk;
    SecureBuffer master;
    std::string passphrase = "correct horse battery staple";
    EXPECT(build_master_key_for_passphrase(passphrase, mk, master, 500));

    // Now build a wallet with that mkey and a single ckey record.
    std::vector<WriteRecord> recs;
    recs.push_back(make_mkey_record(mk));
    uint8_t priv[32] = {0};
    for (int i = 0; i < 32; ++i) priv[i] = uint8_t(i + 1);
    std::vector<uint8_t> ct;
    std::string err;
    EXPECT(encrypt_private_key(master, priv, ct, err));
    WriteRecord cwr;
    cwr.key = std::vector<uint8_t>(PREFIX_CKEY, PREFIX_CKEY + std::strlen(PREFIX_CKEY));
    cwr.key.push_back(0x01); cwr.key.push_back(0x02);
    Serializer sc;
    sc.put_bytes_prefixed(ct);
    cwr.value = sc.take();
    recs.push_back(cwr);

    std::string path = (std::filesystem::temp_directory_path() / "btc_legacy_passphrase_verify_test.dat").string();
    EXPECT(write_bdb_hash_file(path, recs, 4096, &err));

    ParsedWallet pw;
    bool is_bdb = false;
    EXPECT(parse_wallet(path, pw, err, nullptr, &is_bdb));
    EXPECT(pw.encrypted);
    EXPECT(pw.mkey_count == 1);
    EXPECT(pw.ckey_count == 1);

    SecureBuffer derived;
    bool ok = verify_passphrase(pw, passphrase, derived, err);
    EXPECT(ok);
    EXPECT(derived.size() == 32);

    // Now try an incorrect passphrase
    SecureBuffer derived2;
    std::string wrong = "wrong password";
    bool ok2 = verify_passphrase(pw, wrong, derived2, err);
    EXPECT(!ok2);

    remove(path.c_str());
}

TEST(passphrase_verify_wrong_returns_false_not_crash) {
    // The most important property of passphrase verification: a wrong
    // passphrase must NEVER crash, only return false.
    MasterKey mk;
    SecureBuffer master;
    EXPECT(build_master_key_for_passphrase("the-correct-passphrase", mk, master, 250));
    std::vector<WriteRecord> recs;
    recs.push_back(make_mkey_record(mk));
    std::string err;
    std::string path = (std::filesystem::temp_directory_path() / "btc_legacy_passphrase_wrong_test.dat").string();
    EXPECT(write_bdb_hash_file(path, recs, 4096, &err));
    ParsedWallet pw;
    bool is_bdb = false;
    EXPECT(parse_wallet(path, pw, err, nullptr, &is_bdb));
    EXPECT(pw.encrypted);

    // Several wrong passphrases
    for (const char* w : {"wrong", "", "x", "the-correct-passphrase-but-with-extra",
                          "a-very-long-but-still-wrong-passphrase-value-here"}) {
        SecureBuffer derived;
        std::string wrong = w;
        bool ok = verify_passphrase(pw, wrong, derived, err);
        EXPECT(!ok);
        EXPECT(derived.empty());
    }
    remove(path.c_str());
}
