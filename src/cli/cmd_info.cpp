// src/cli/cmd_info.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include <iostream>
#include <cstring>
#include <string>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_info(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy info <wallet.dat> [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    if (!util::file_exists(path)) {
        std::cerr << "Error: file not found: " << path << "\n";
        return ExitCode::FILE_NOT_FOUND;
    }
    std::string err;
    wallet::ParsedWallet w;
    bool is_bdb = false;
    if (!wallet::parse_wallet(path, w, err, nullptr, &is_bdb)) {
        std::cerr << "Error: " << err << "\n";
        return ExitCode::UNSUPPORTED_WALLET;
    }
    auto size = util::file_size(path);
    if (g_json_mode) {
        util::JsonObject o;
        o["file"] = path;
        o["file_size"] = uint64_t(size);
        o["format"] = is_bdb ? "berkeley-db" : "unknown";
        o["wallet_type"] = "legacy";
        o["encrypted"] = w.encrypted;
        if (w.wallet_version) o["wallet_version"] = int64_t(w.wallet_version);
        o["compatibility"] = wallet::compatibility_string(w.compat);
        util::JsonObject rec;
        for (auto& kv : w.record_counts) {
            rec[kv.first] = int64_t(kv.second);
        }
        o["records"] = rec;
        if (!w.warnings.empty()) {
            util::JsonArray warns;
            for (auto& s : w.warnings) warns.emplace_back(s);
            o["warnings"] = warns;
        }
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Bitcoin Legacy Wallet Info\n\n";
        std::cout << "File size         : " << size << " bytes\n";
        std::cout << "Database format   : " << (is_bdb ? "Berkeley DB (hash)" : "Unknown") << "\n";
        std::cout << "Wallet type       : Legacy\n";
        std::cout << "Encryption        : " << (w.encrypted ? "YES" : "NO") << "\n";
        std::cout << "Wallet version    : " << (w.wallet_version ? std::to_string(w.wallet_version) : std::string("(none)")) << "\n";
        std::cout << "Key count         : " << w.key_count << "\n";
        std::cout << "Encrypted-key cnt : " << w.ckey_count << "\n";
        std::cout << "Transaction count : " << w.tx_count << "\n";
        std::cout << "Compatibility     : " << wallet::compatibility_string(w.compat) << "\n";
        std::cout << "\nRecord counts:\n";
        for (auto& kv : w.record_counts) {
            std::cout << "  " << kv.first << " : " << kv.second << "\n";
        }
        if (!w.warnings.empty()) {
            std::cout << "\nWarnings:\n";
            for (auto& s : w.warnings) std::cout << "  - " << s << "\n";
        }
    }
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
