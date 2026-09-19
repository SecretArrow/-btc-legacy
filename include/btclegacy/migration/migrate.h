// btclegacy/migration/migrate.h
#pragma once
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/platform/secure_memory.h"
#include <string>
#include <vector>
#include <optional>

namespace btclegacy::migration {

struct MigrationReport {
    std::string source_path;
    std::string destination_path;
    std::string backup_path;
    bool   detect_ok = false;
    bool   validate_ok = false;
    bool   read_ok = false;
    bool   decrypt_ok = false;
    bool   extract_ok = false;
    bool   create_dest_ok = false;
    bool   verify_dest_ok = false;
    bool   full_migration = false; // true if every record migrated
    uint32_t source_records = 0;
    uint32_t migrated_records = 0;
    uint32_t skipped_records = 0;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

// Migrate a legacy wallet to a portable JSON descriptor at --out path.
// The destination is a JSON file containing the migrated material in
// plain "Bitcoin Core-like" JSON (no encryption on the destination,
// because the user explicitly provided the passphrase — we warn them
// to handle the destination file carefully).
//
// The source is never modified.
bool migrate_wallet(const std::string& src,
                    const std::string& out_path,
                    const std::optional<std::string>& passphrase,
                    bool yes,
                    MigrationReport& report,
                    std::string& err);

} // namespace btclegacy::migration
