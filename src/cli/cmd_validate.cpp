// src/cli/cmd_validate.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/bdb/bdb_validator.h"
#include <iostream>
#include <cstring>
#include <string>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_validate(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy validate <wallet.dat> [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    if (!util::file_exists(path)) {
        std::cerr << "Error: file not found: " << path << "\n";
        return ExitCode::FILE_NOT_FOUND;
    }
    std::string err;
    bdb::ValidationReport br = bdb::validate_bdb(path, err, g_verbose_mode);
    wallet::ParsedWallet w;
    bool is_bdb = false;
    wallet::parse_wallet(path, w, err, nullptr, &is_bdb);

    // Sanity: in an encrypted wallet, every "ckey" should have a matching "key" entry
    bool key_ckey_relationship_ok = true;
    if (w.ckey_count > 0 && w.key_count == 0 && !w.encrypted) {
        key_ckey_relationship_ok = false;
    }
    bool mkey_ok = (!w.encrypted) || (w.encrypted && !w.master_keys.empty() &&
                                       w.master_keys[0].valid);
    bool records_ok = (br.corrupt_pages == 0) && w.errors.empty();
    bool overall_ok = br.bdb_structure_ok && br.readable && mkey_ok &&
                      key_ckey_relationship_ok && records_ok;
    bool partially_recoverable = br.partially_recoverable ||
                                 (!records_ok && br.records > 0);
    const char* result = overall_ok ? "VALID" :
                         (partially_recoverable ? "PARTIALLY RECOVERABLE" : "INVALID");

    if (g_json_mode) {
        util::JsonObject o;
        o["wallet"] = path;
        o["database"] = br.bdb_structure_ok ? "OK" : "FAILED";
        o["bdb_structure"] = br.bdb_structure_ok ? "OK" : "FAILED";
        o["records"] = records_ok ? "OK" : "FAILED";
        o["encryption_metadata"] = mkey_ok ? "OK" : "FAILED";
        o["key_count"] = int64_t(w.key_count);
        o["ckey_count"] = int64_t(w.ckey_count);
        o["mkey_count"] = int64_t(w.mkey_count);
        o["tx_count"] = int64_t(w.tx_count);
        o["corrupt_pages"] = int64_t(br.corrupt_pages);
        o["result"] = result;
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Wallet validation\n\n";
        std::cout << "Database             : " << (br.bdb_structure_ok ? "OK" : "FAILED") << "\n";
        std::cout << "BDB structure        : " << (br.bdb_structure_ok ? "OK" : "FAILED") << "\n";
        std::cout << "Wallet records       : " << (records_ok ? "OK" : "FAILED") << "\n";
        std::cout << "Encryption metadata  : " << (mkey_ok ? "OK" : "FAILED") << "\n";
        std::cout << "Key records          : " << w.key_count << "\n";
        std::cout << "Encrypted keys       : " << w.ckey_count << "\n";
        std::cout << "Transactions         : " << w.tx_count << "\n";
        std::cout << "Corrupt pages        : " << br.corrupt_pages << "\n";
        std::cout << "\nResult: " << result << "\n";
        if (!br.warnings.empty()) {
            std::cout << "\nWarnings:\n";
            for (auto& s : br.warnings) std::cout << "  - " << s << "\n";
        }
    }
    if (overall_ok) return ExitCode::SUCCESS;
    if (partially_recoverable) return ExitCode::CORRUPTED_WALLET;
    return ExitCode::CORRUPTED_WALLET;
}

} // namespace btclegacy::cli
