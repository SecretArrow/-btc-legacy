// tests/unit/test_wallet_records.cpp
#include "test_macros.h"
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/bdb/bdb_writer.h"
#include "btclegacy/util/file_util.h"
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>

using namespace btclegacy::wallet;
using namespace btclegacy::bdb;
using namespace btclegacy::util;

TEST(wallet_split_prefix_key) {
    std::vector<uint8_t> k = {'k','e','y', 0x01, 0x02, 0x03};
    std::string prefix;
    std::vector<uint8_t> suffix;
    EXPECT(split_wallet_key(k, prefix, suffix));
    EXPECT_STR_EQ(prefix, "key");
    EXPECT(suffix.size() == 3);
    EXPECT(suffix[0] == 0x01);
}

TEST(wallet_split_prefix_version) {
    std::vector<uint8_t> k = {'v','e','r','s','i','o','n'};
    std::string prefix;
    std::vector<uint8_t> suffix;
    EXPECT(split_wallet_key(k, prefix, suffix));
    EXPECT_STR_EQ(prefix, "version");
    EXPECT(suffix.empty());
}

TEST(wallet_parse_uint32) {
    std::vector<uint8_t> v = {0x60, 0xEA, 0x00, 0x00};
    uint32_t x = 0;
    EXPECT(try_parse_uint32(v, x));
    EXPECT(x == 60000);
}

TEST(wallet_parser_end_to_end) {
    // Build a synthetic wallet.dat with version + a couple of key
    // records, then parse it and verify counts.
    std::vector<WriteRecord> recs;
    {
        WriteRecord w;
        w.key = std::vector<uint8_t>(PREFIX_VERSION, PREFIX_VERSION + std::strlen(PREFIX_VERSION));
        w.value = {0x60, 0xEA, 0x00, 0x00}; // 60000 LE
        recs.push_back(w);
    }
    {
        WriteRecord w;
        w.key = std::vector<uint8_t>(PREFIX_DEFAULTKEY, PREFIX_DEFAULTKEY + std::strlen(PREFIX_DEFAULTKEY));
        w.value = std::vector<uint8_t>(33, 0x02);
        recs.push_back(w);
    }
    for (int i = 0; i < 3; ++i) {
        WriteRecord w;
        w.key = std::vector<uint8_t>(PREFIX_KEY, PREFIX_KEY + std::strlen(PREFIX_KEY));
        w.key.push_back(uint8_t(i));
        w.value = std::vector<uint8_t>(33, uint8_t(i));
        recs.push_back(w);
    }
    std::string err;
    std::string path = (std::filesystem::temp_directory_path() / "btc_legacy_wallet_parser_e2e.dat").string();
    EXPECT(write_bdb_hash_file(path, recs, 4096, &err));
    ParsedWallet w;
    bool is_bdb = false;
    EXPECT(parse_wallet(path, w, err, nullptr, &is_bdb));
    EXPECT(is_bdb);
    EXPECT(w.wallet_version == 60000);
    EXPECT(w.key_count == 3);
    EXPECT(w.defaultkey_present);
    EXPECT(w.record_counts.count("version"));
    EXPECT(!w.encrypted);
    EXPECT(w.compat == ParsedWallet::Compatibility::EARLY_BITCOIN);
    remove(path.c_str());
}

TEST(wallet_parser_unknown_records_preserved) {
    // Ensure unknown records are NOT silently discarded
    std::vector<WriteRecord> recs;
    WriteRecord w;
    w.key = std::vector<uint8_t>({'f','o','o','b','a','r'});
    w.value = std::vector<uint8_t>({'d','a','t','a'});
    recs.push_back(w);
    std::string err;
    std::string path = (std::filesystem::temp_directory_path() / "btc_legacy_wallet_unknown_test.dat").string();
    EXPECT(write_bdb_hash_file(path, recs, 4096, &err));
    ParsedWallet pw;
    bool is_bdb = false;
    EXPECT(parse_wallet(path, pw, err, nullptr, &is_bdb));
    EXPECT(pw.unknown_records.size() == 1);
    EXPECT_STR_EQ(pw.unknown_records[0].first, "foobar");
    EXPECT(pw.compat == ParsedWallet::Compatibility::UNSUPPORTED);
    remove(path.c_str());
}
