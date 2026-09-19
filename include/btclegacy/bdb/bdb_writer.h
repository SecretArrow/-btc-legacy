// btclegacy/bdb/bdb_writer.h
#pragma once
//
// Minimal BDB hash file *writer*. Used by `btc-legacy create` to emit
// synthetic test fixtures that look like real legacy Bitcoin wallets
// (same page-size, same metadata page layout, same hash data pages).
//
// This is NOT a general-purpose BDB writer; it only emits a simple,
// single-bucket-set hash file that the project's own Reader can also
// consume. Real Bitcoin wallets produced by libdb contain additional
// structure (multiple hash buckets, overflow chains, etc.) but the
// page layout that *our* reader relies on is the same.
//
#include "btclegacy/bdb/bdb_database.h"
#include <string>
#include <vector>
#include <cstdint>

namespace btclegacy::bdb {

struct WriteRecord {
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
};

// Create a BDB hash file at the given path containing the supplied records.
// Returns false on I/O error.
bool write_bdb_hash_file(const std::string& path,
                         const std::vector<WriteRecord>& records,
                         uint32_t pagesize = WALLET_DEFAULT_PAGESIZE,
                         std::string* err = nullptr);

} // namespace btclegacy::bdb
