// btclegacy/recovery/recover.h
#pragma once
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/platform/secure_memory.h"
#include <string>
#include <vector>
#include <optional>

namespace btclegacy::recovery {

struct RecoveryReport {
    bool     bdb_readable = false;
    bool     wallet_records_present = false;  // true if any wallet prefix found
    bool     wallet_records_full = false;     // true if no errors
    bool     master_key_present = false;
    bool     encrypted_keys_present = false;
    uint32_t total_records = 0;
    uint32_t recovered_records = 0;
    uint32_t corrupted_records = 0;
    uint32_t pages_read = 0;
    uint32_t pages_with_errors = 0;
    std::vector<std::string> recovered_record_summary; // human-readable
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::string backup_path; // if a backup was created for recovery work
    enum class Result {
        OK,                       // file intact, all records read
        PARTIALLY_RECOVERABLE,    // some records recovered, some lost
        UNRECOVERABLE,            // BDB too corrupt to read
    } result = Result::UNRECOVERABLE;
};

// Recover readable records from a (possibly damaged) wallet file.
// ALWAYS read-only against the source. If `work_on_copy` is true,
// the function creates a temporary copy and operates on it.
//
// If the user supplied a passphrase and the wallet is encrypted,
// the recovered ckey records are decrypted (their decrypted form is
// NOT stored in the report — only summary counts).
bool recover_wallet(const std::string& path,
                    const std::optional<std::string>& passphrase,
                    bool work_on_copy,
                    RecoveryReport& out,
                    std::string& err);

} // namespace btclegacy::recovery
