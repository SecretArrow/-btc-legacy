// btclegacy/bdb/bdb_validator.h
#pragma once
#include "btclegacy/bdb/bdb_reader.h"
#include <string>
#include <vector>

namespace btclegacy::bdb {

struct ValidationReport {
    bool     bdb_structure_ok = false;
    bool     metadata_ok = false;
    bool     readable = false;
    uint32_t total_pages = 0;
    uint32_t hash_data_pages = 0;
    uint32_t overflow_pages = 0;
    uint32_t free_pages = 0;
    uint32_t corrupt_pages = 0;
    uint32_t records = 0;
    std::vector<std::string> warnings;
    bool     partially_recoverable = false;
};

ValidationReport validate_bdb(const std::string& path,
                              std::string& err,
                              bool verbose = false);

} // namespace btclegacy::bdb
