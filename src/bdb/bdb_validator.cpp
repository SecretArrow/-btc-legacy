// src/bdb/bdb_validator.cpp
#include "btclegacy/bdb/bdb_validator.h"
#include "btclegacy/util/strings.h"

namespace btclegacy::bdb {

ValidationReport validate_bdb(const std::string& path, std::string& err, bool verbose) {
    ValidationReport r;
    Reader rd;
    if (!rd.open(path, err)) {
        r.bdb_structure_ok = false;
        r.metadata_ok = false;
        r.readable = false;
        return r;
    }
    r.readable = true;
    r.bdb_structure_ok = true;
    r.metadata_ok = true;
    r.total_pages = rd.stats().total_pages;

    // Iterate every page; classify.
    uint32_t total_records = 0;
    auto cb = [&](const Record& rec) {
        total_records++;
        return true;
    };
    std::string iterr;
    rd.for_each_record(cb, iterr, {});
    r.hash_data_pages = rd.stats().hash_data_pages;
    r.overflow_pages  = rd.stats().overflow_pages;
    r.free_pages      = rd.stats().free_pages;
    r.corrupt_pages   = rd.stats().errors;
    r.records         = total_records;

    if (r.corrupt_pages > 0) {
        r.partially_recoverable = true;
        r.warnings.push_back("Some pages contained recoverable data but "
                             "had corrupted item slots that were skipped.");
    }
    if (!iterr.empty()) {
        r.warnings.push_back(iterr);
    }
    if (verbose) {
        r.warnings.push_back("magic=" + util::to_hex(
            reinterpret_cast<const uint8_t*>(&rd.meta().magic), 4));
        r.warnings.push_back("version=" + std::to_string(rd.meta().version));
        r.warnings.push_back("pagesize=" + std::to_string(rd.meta().pagesize));
        r.warnings.push_back("last_pgno=" + std::to_string(rd.meta().last_pgno));
    }
    return r;
}

} // namespace btclegacy::bdb
