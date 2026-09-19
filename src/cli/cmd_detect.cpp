// src/cli/cmd_detect.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/bdb/bdb_reader.h"
#include <iostream>
#include <cstring>
#include <string>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_detect(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy detect <wallet.dat> [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    if (!util::file_exists(path)) {
        if (g_json_mode) {
            util::JsonObject o; o["error"] = "file not found"; o["path"] = path;
            std::cout << util::JsonValue(o).to_string() << "\n";
        } else {
            std::cerr << "Error: file not found: " << path << "\n";
        }
        return ExitCode::FILE_NOT_FOUND;
    }
    std::string err;
    wallet::ParsedWallet w;
    bool is_bdb = false;
    if (!wallet::parse_wallet(path, w, err, nullptr, &is_bdb)) {
        if (g_json_mode) {
            util::JsonObject o; o["error"] = err; o["path"] = path;
            o["is_bdb"] = is_bdb;
            std::cout << util::JsonValue(o).to_string() << "\n";
        } else {
            std::cerr << "Bitcoin Legacy Wallet Analyzer\n\n"
                      << "File         : " << path << "\n"
                      << "Format       : " << (is_bdb ? "Berkeley DB" : "Unknown") << "\n"
                      << "Status       : FAILED (" << err << ")\n";
        }
        return ExitCode::UNSUPPORTED_WALLET;
    }
    std::string compat = wallet::compatibility_string(w.compat);
    if (g_json_mode) {
        util::JsonObject o;
        o["file"] = path;
        o["format"] = is_bdb ? "berkeley-db" : "unknown";
        o["wallet_type"] = "legacy";
        o["encrypted"] = w.encrypted;
        o["compatibility"] = compat;
        o["status"] = std::string("DETECTED");
        if (w.wallet_version) {
            o["wallet_version"] = int64_t(w.wallet_version);
        }
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Bitcoin Legacy Wallet Analyzer\n\n";
        std::cout << "File         : " << path << "\n";
        std::cout << "Format       : " << (is_bdb ? "Berkeley DB" : "Unknown") << "\n";
        std::cout << "Wallet type  : Legacy\n";
        std::cout << "Encryption   : " << (w.encrypted ? "YES" : "NO") << "\n";
        std::cout << "Compatibility: " << compat << "\n";
        std::cout << "Status       : DETECTED\n";
    }
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
