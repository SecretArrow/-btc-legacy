// btclegacy/bdb/bdb_database.h
#pragma once
//
// Low-level representation of a Berkeley DB "hash" database file
// (the format historically used by Bitcoin Core's wallet.dat between
// 2009 and ~2015).
//
// Reference: Berkeley DB 4.x dbinc/db_page.h, dbinc/db_am.h, src/db/db_meta.c
// and src/hash/hash*.c. The Bitcoin Core client opened its wallet
// with DB->open(... DB_HASH, ...) and let the default DB_HASH parameters
// (page_size 4096, fill factor, etc.) apply.
//
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>

namespace btclegacy::bdb {

// Common page types (dbinc/db_page.h)
constexpr uint8_t PAGE_TYPE_INVALID        = 0;
constexpr uint8_t PAGE_TYPE_HASHMETA       = 8;
constexpr uint8_t PAGE_TYPE_HASH_UNSORTED  = 13;
constexpr uint8_t PAGE_TYPE_LHASH          = 14; // sorted hash leaf

// Database magic numbers (dbinc/db_am.h)
constexpr uint32_t DB_HASHMAGIC  = 0x00061561; // Berkeley DB hash
constexpr uint32_t DB_BTREEMAGIC = 0x00053162;
constexpr uint32_t DB_QAMMAGIC   = 0x00041504;
constexpr uint32_t DB_RECNO      = 0x00044221;

// Defaults used by Bitcoin Core's wallet.dat
constexpr uint32_t WALLET_DEFAULT_PAGESIZE = 4096;

// Metadata about a single BDB page.
struct PageHeader {
    uint64_t lsn = 0;
    uint32_t pgno = 0;
    uint32_t prev_pgno = 0;
    uint32_t next_pgno = 0;
    uint16_t entries = 0;
    uint16_t hf_offset = 0;
    uint8_t  level = 0;
    uint8_t  type = 0;
};

// Database-level metadata parsed from page 0.
struct DatabaseMeta {
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t pagesize = 0;
    uint8_t  encrypt_alg = 0;
    uint8_t  page_type = 0;
    uint8_t  metaflags = 0;
    uint32_t flags = 0;
    uint32_t last_pgno = 0;
    uint32_t keycount = 0;
    uint32_t record_count = 0;
    // Hash-specific (best-effort offsets, may not all be present)
    uint32_t maxbucket = 0;
    uint32_t high_mask = 0;
    uint32_t low_mask  = 0;
    uint32_t ffactor    = 0;
    uint32_t nelem      = 0;
    uint32_t h_charkey  = 0;
};

// A single BDB key/data record.
struct Record {
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
    uint32_t page = 0;     // page number where this record was read
    uint16_t slot = 0;     // slot within the page
    bool overflow = false; // value came from an overflow page
};

// Item types inside hash pages (BKEYDATA.type)
constexpr uint16_t BKEYDATA_KEYDATA   = 1;
constexpr uint16_t BKEYDATA_DUPLICATE = 2;
constexpr uint16_t BKEYDATA_OVERFLOW  = 3;

} // namespace btclegacy::bdb
