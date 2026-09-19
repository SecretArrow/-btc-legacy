// src/recovery/recover.cpp — implements the recovery::recover_wallet
// helper. The CLI command handler in cmd_recover.cpp builds the report
// inline; this file exposes a programmatic API for tests.
#include "btclegacy/recovery/recover.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/bdb/bdb_reader.h"
#include "btclegacy/bdb/bdb_validator.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/sha256.h"
#include "btclegacy/util/time_util.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/crypto/passphrase.h"
#include <string>
#include <vector>

namespace btclegacy::recovery {

bool recover_wallet(const std::string& path,
                    const std::optional<std::string>& passphrase,
                    bool work_on_copy,
                    RecoveryReport& out,
                    std::string& err) {
    out = RecoveryReport{};
    if (!util::file_exists(path)) { err = "file not found"; return false; }

    std::string effective_path = path;
    if (work_on_copy) {
        std::string stamp = util::format_timestamp(util::now_unix_seconds(), "%Y%m%d-%H%M%S");
        out.backup_path = path + ".recover-copy-" + stamp;
        if (!util::copy_file(path, out.backup_path)) {
            err = "failed to create recovery copy";
            return false;
        }
        effective_path = out.backup_path;
    }
    // Validate BDB
    bdb::ValidationReport br = bdb::validate_bdb(effective_path, err, false);
    out.bdb_readable = br.readable;
    out.pages_read = br.total_pages;
    out.pages_with_errors = br.corrupt_pages;

    // Parse wallet
    wallet::ParsedWallet w;
    bool is_bdb = false;
    bool parsed = wallet::parse_wallet(effective_path, w, err, nullptr, &is_bdb);
    out.wallet_records_present = parsed;
    out.wallet_records_full = parsed && br.corrupt_pages == 0;
    out.master_key_present = !w.master_keys.empty();
    out.encrypted_keys_present = !w.ckeys.empty();
    out.total_records = uint32_t(br.records);
    out.recovered_records = uint32_t(br.records - br.corrupt_pages);
    out.corrupted_records = br.corrupt_pages;
    for (auto& s : br.warnings) out.warnings.push_back(s);

    // Decrypt if passphrase provided
    if (passphrase && w.encrypted) {
        platform::SecureBuffer master;
        std::string perr;
        bool ok = wallet::verify_passphrase(w, *passphrase, master, perr);
        if (ok) {
            out.recovered_record_summary.push_back(
                "Decrypted " + std::to_string(w.ckeys.size()) + " encrypted keys");
        } else {
            out.errors.push_back("passphrase verification failed: " + perr);
        }
    }

    if (br.corrupt_pages == 0) out.result = RecoveryReport::Result::OK;
    else if (br.records > 0) out.result = RecoveryReport::Result::PARTIALLY_RECOVERABLE;
    else out.result = RecoveryReport::Result::UNRECOVERABLE;

    return true;
}

} // namespace btclegacy::recovery
