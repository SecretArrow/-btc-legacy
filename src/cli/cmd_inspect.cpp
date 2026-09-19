// src/cli/cmd_inspect.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include <iostream>
#include <cstring>
#include <string>
#include <map>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_inspect(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy inspect <wallet.dat> "
                     "[--metadata-only] [--records] [--json] [--verbose]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    bool metadata_only = false;
    bool records = false;
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--metadata-only") metadata_only = true;
        else if (a == "--records")  records = true;
    }
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
    if (g_json_mode) {
        util::JsonObject o;
        o["file"] = path;
        o["encrypted"] = w.encrypted;
        if (w.wallet_version) o["wallet_version"] = int64_t(w.wallet_version);
        o["compatibility"] = wallet::compatibility_string(w.compat);
        if (metadata_only) {
            // Just metadata
            util::JsonObject meta;
            meta["key_count"] = int64_t(w.key_count);
            meta["ckey_count"] = int64_t(w.ckey_count);
            meta["mkey_count"] = int64_t(w.mkey_count);
            meta["tx_count"]  = int64_t(w.tx_count);
            meta["name_count"] = int64_t(w.name_count);
            meta["pool_count"] = int64_t(w.pool_count);
            meta["defaultkey_present"] = bool(w.defaultkey_present);
            meta["watchonly_count"] = int64_t(w.watchonly_count);
            meta["hd_chain_present"] = bool(w.hd_chain_present);
            o["metadata"] = meta;
        } else {
            util::JsonArray rec_arr;
            auto add = [&](const std::string& prefix, const std::map<std::string, std::string>& fields) {
                util::JsonObject r; r["prefix"] = prefix;
                for (auto& kv : fields) r[kv.first] = kv.second;
                rec_arr.emplace_back(r);
            };
            if (records) {
                add("version", {{"value", std::to_string(w.wallet_version)}});
                add("defaultkey", {{"present", std::to_string(w.defaultkey_present)}});
                add("mkey",  {{"count", std::to_string(w.mkey_count)}});
                add("key",   {{"count", std::to_string(w.key_count)}});
                add("ckey",  {{"count", std::to_string(w.ckey_count)}});
                add("pool",  {{"count", std::to_string(w.pool_count)}});
                add("tx",    {{"count", std::to_string(w.tx_count)}});
                add("name",  {{"count", std::to_string(w.name_count)}});
            }
            o["records"] = rec_arr;
        }
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Bitcoin Legacy Wallet Inspect\n\n";
        std::cout << "File             : " << path << "\n";
        std::cout << "Wallet version   : " << (w.wallet_version ? std::to_string(w.wallet_version) : std::string("(none)")) << "\n";
        std::cout << "Encrypted        : " << (w.encrypted ? "YES" : "NO") << "\n";
        std::cout << "Compatibility    : " << wallet::compatibility_string(w.compat) << "\n";
        std::cout << "Records summary  :\n";
        for (auto& kv : w.record_counts) {
            std::cout << "  " << kv.first << " : " << kv.second << "\n";
        }
        // For "key" / "ckey" records we redact the actual bytes.
        std::cout << "Note: Sensitive fields are redacted by default. Use --records "
                     "for per-record summaries. Use --passphrase to enable decrypted "
                     "private-key inspection (not implemented in inspect).\n";
    }
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
