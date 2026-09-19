// btclegacy/bdb/bdb_reader.h
#pragma once
//
// Read-only BDB "hash" file reader. Designed to:
//
//   * Detect Berkeley DB metadata page
//   * Validate page count, page size
//   * Iterate over every data page and yield (key, value) pairs
//   * Handle hash unsorted (legacy Bitcoin 2009-2015) and sorted hash pages
//   * Handle on-page overflow items
//   * Tolerate partial corruption (yield errors per-page)
//   * NEVER modify the file
//
#include "btclegacy/bdb/bdb_database.h"
#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <system_error>

namespace btclegacy::bdb {

enum class ReaderError {
    None = 0,
    FileNotFound,
    NotBdb,
    UnknownMagic,
    UnsupportedPageSize,
    Truncated,
    PageHeaderInvalid,
    SlotOutOfBounds,
    OverflowLinkBroken,
    DecompressionError,
};

struct ReadStats {
    uint32_t total_pages = 0;
    uint32_t hash_data_pages = 0;
    uint32_t metadata_pages = 0;
    uint32_t overflow_pages = 0;
    uint32_t free_pages = 0;
    uint32_t records = 0;
    uint32_t errors = 0;
};

class Reader {
public:
    Reader();
    ~Reader();

    // Open file for read-only access. Pages are read on-demand.
    bool open(const std::string& path, std::string& err);
    void close();

    bool is_open() const { return fd_ >= 0; }

    const DatabaseMeta& meta() const { return meta_; }
    const ReadStats& stats() const { return stats_; }

    // Read a specific page by number into out (size = pagesize).
    bool read_page(uint32_t pgno, std::vector<uint8_t>& out, std::string& err) const;

    // Parse page header from raw page bytes
    bool parse_page_header(const std::vector<uint8_t>& page, PageHeader& hdr, std::string& err) const;

    // Iterate all (key, value) pairs. The callback returns false to stop.
    // Records that fail to parse are skipped and counted in stats.errors.
    bool for_each_record(const std::function<bool(const Record&)>& cb,
                         std::string& err,
                         const std::function<void(int pct)>& progress = {});

    // Convenience: load all records into memory.
    bool load_all(std::vector<Record>& out, std::string& err);

    // Load a single page's content as records (helper for inspect).
    bool read_page_records(uint32_t pgno, std::vector<Record>& out, std::string& err) const;

private:
    bool parse_meta_page_(const std::vector<uint8_t>& p, DatabaseMeta& m, std::string& err) const;
    bool parse_data_page_(const std::vector<uint8_t>& p,
                          std::vector<Record>& out,
                          std::string& err) const;
    bool read_overflow_chain_(uint32_t first_pgno, std::vector<uint8_t>& out, std::string& err) const;

    int fd_ = -1;
    uint64_t file_size_ = 0;
    DatabaseMeta meta_{};
    mutable ReadStats stats_{};
    std::string path_;
};

} // namespace btclegacy::bdb
