// tests/fuzz/fuzz_passphrase.cpp
//
// Fuzz the passphrase verification path. Build a wallet with an mkey
// derived from a known passphrase, then supply arbitrary byte streams
// as candidate "passphrases" and confirm verify_passphrase() returns
// false (never crashes).
//
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/parser/serializer.h"
#include "btclegacy/bdb/bdb_writer.h"
#include "btclegacy/wallet/wallet_parser.h"
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>

int fuzz_passphrase_verify(const std::vector<uint8_t>& data) {
    static bool init = false;
    static btclegacy::wallet::ParsedWallet wallet;
    static std::string wallet_path = (std::filesystem::temp_directory_path() / "btc_legacy_fuzz_passphrase_wallet.dat").string();
    if (!init) {
        btclegacy::wallet::MasterKey mk;
        btclegacy::platform::SecureBuffer master;
        if (!btclegacy::wallet::build_master_key_for_passphrase("known-passphrase-123", mk, master, 250))
            return 0;
        std::vector<btclegacy::bdb::WriteRecord> recs;
        btclegacy::bdb::WriteRecord wr;
        wr.key = std::vector<uint8_t>(btclegacy::wallet::PREFIX_MKEY,
            btclegacy::wallet::PREFIX_MKEY + std::strlen(btclegacy::wallet::PREFIX_MKEY));
        wr.key.push_back(0); wr.key.push_back(0); wr.key.push_back(0); wr.key.push_back(1);
        btclegacy::parser::Serializer s;
        s.put_bytes_prefixed(mk.vchCryptedKey);
        s.put_bytes_prefixed(mk.vchSalt);
        s.put_u32(mk.nDerivationMethod);
        s.put_u32(mk.nDeriveCount);
        wr.value = s.take();
        recs.push_back(wr);
        std::string err;
        btclegacy::bdb::write_bdb_hash_file(wallet_path, recs, 4096, &err);
        bool is_bdb = false;
        btclegacy::wallet::parse_wallet(wallet_path, wallet, err, nullptr, &is_bdb);
        init = true;
    }
    // Convert arbitrary bytes into a string passphrase and verify
    std::string candidate(reinterpret_cast<const char*>(data.data()), data.size());
    btclegacy::platform::SecureBuffer derived;
    std::string err;
    bool ok = btclegacy::wallet::verify_passphrase(wallet, candidate, derived, err);
    (void)ok; // we don't care about correctness, only about no crash
    return 0;
}
