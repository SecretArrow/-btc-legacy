// tests/unit/test_bdb_writer_reader.cpp
#include "test_macros.h"
#include "btclegacy/bdb/bdb_writer.h"
#include "btclegacy/bdb/bdb_reader.h"
#include "btclegacy/wallet/wallet_record.h"
#include <vector>
#include <string>
#include <cstring>

using namespace btclegacy::bdb;
using namespace btclegacy::wallet;

TEST(bdb_writer_empty_then_read) {
    std::vector<WriteRecord> recs;
    std::string err;
    std::string path = "/tmp/btc_legacy_bdb_empty_test.dat";
    bool ok = write_bdb_hash_file(path, recs, 4096, &err);
    EXPECT(ok);
    if (!ok) return;
    Reader r;
    std::string rerr;
    EXPECT(r.open(path, rerr));
    EXPECT(r.is_open());
    std::vector<Record> out;
    r.load_all(out, rerr);
    EXPECT(out.empty());
    r.close();
    remove(path.c_str());
}

TEST(bdb_writer_simple_roundtrip) {
    WriteRecord a;
    a.key  = {'k','e','y',0,1,2,3};
    a.value = {0xAA,0xBB,0xCC};
    WriteRecord b;
    b.key  = {'n','a','m','e',0x01,0x02};
    b.value = {'A','d','d','r','e','s','s',' ','1'};
    std::vector<WriteRecord> recs = {a, b};
    std::string err;
    std::string path = "/tmp/btc_legacy_bdb_simple_test.dat";
    bool ok = write_bdb_hash_file(path, recs, 4096, &err);
    EXPECT(ok);
    if (!ok) return;
    Reader r;
    std::string rerr;
    EXPECT(r.open(path, rerr));
    std::vector<Record> out;
    r.load_all(out, rerr);
    EXPECT(out.size() == 2);
    // First record
    if (out.size() >= 1) {
        EXPECT(out[0].key.size() == 7);
        EXPECT(out[0].value.size() == 3);
        EXPECT(out[0].key[3] == 0);
        EXPECT(out[0].value[0] == 0xAA);
    }
    if (out.size() >= 2) {
        EXPECT(out[1].value.size() == 9);
        EXPECT(out[1].value[0] == 'A');
    }
    r.close();
    remove(path.c_str());
}

TEST(bdb_writer_large_record_set) {
    // 50 records to test multi-page handling
    std::vector<WriteRecord> recs;
    for (int i = 0; i < 50; ++i) {
        WriteRecord r;
        r.key = {'k','e','y', uint8_t(i & 0xff), uint8_t((i>>8) & 0xff)};
        r.value = std::vector<uint8_t>(64, uint8_t(i));
        recs.push_back(r);
    }
    std::string err;
    std::string path = "/tmp/btc_legacy_bdb_large_test.dat";
    bool ok = write_bdb_hash_file(path, recs, 4096, &err);
    EXPECT(ok);
    if (!ok) return;
    Reader r;
    std::string rerr;
    EXPECT(r.open(path, rerr));
    std::vector<Record> out;
    r.load_all(out, rerr);
    EXPECT(out.size() == 50);
    r.close();
    remove(path.c_str());
}

TEST(bdb_writer_wallet_records) {
    // Build a synthetic wallet with all major prefixes
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
        w.value = std::vector<uint8_t>(33, 0x02); // compressed pubkey placeholder
        recs.push_back(w);
    }
    for (int i = 0; i < 5; ++i) {
        WriteRecord w;
        w.key = std::vector<uint8_t>(PREFIX_KEY, PREFIX_KEY + std::strlen(PREFIX_KEY));
        w.key.push_back(uint8_t(i));
        w.value = std::vector<uint8_t>(33, uint8_t(i));
        recs.push_back(w);
    }
    std::string err;
    std::string path = "/tmp/btc_legacy_bdb_wallet_test.dat";
    EXPECT(write_bdb_hash_file(path, recs, 4096, &err));
    Reader r;
    std::string rerr;
    EXPECT(r.open(path, rerr));
    std::vector<Record> out;
    r.load_all(out, rerr);
    EXPECT(out.size() == 7);
    r.close();
    remove(path.c_str());
}
