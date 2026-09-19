// tests/fuzz/fuzz_bdb_parse.cpp
//
// Fuzz the BDB reader against arbitrary byte streams. The fuzz
// target's contract is: it must NEVER crash (no segfaults, no
// use-after-free, no buffer overflow). Returning a non-zero exit
// code is allowed — but a crash is a finding.
//
#include "btclegacy/bdb/bdb_reader.h"
#include "btclegacy/util/file_util.h"
#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <filesystem>

int fuzz_bdb_parse(const std::vector<uint8_t>& data) {
    // Write the data to a temp file, then attempt to open + iterate.
    static const std::string tmp = (std::filesystem::temp_directory_path() / "btc_legacy_fuzz_bdb.dat").string();
    if (!btclegacy::util::write_all(tmp, data)) return 0;
    btclegacy::bdb::Reader r;
    std::string err;
    if (!r.open(tmp, err)) {
        remove(tmp.c_str());
        return 0; // not a BDB file — fine
    }
    std::vector<btclegacy::bdb::Record> recs;
    r.load_all(recs, err);
    r.close();
    remove(tmp.c_str());
    return 0;
}
