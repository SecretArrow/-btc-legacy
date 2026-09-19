// src/cli/cmd_version.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include <iostream>

namespace btclegacy::cli {

extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;

void apply_global_flags_for_subcommand(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--json") g_json_mode = true;
        else if (a == "--verbose") g_verbose_mode = true;
        else if (a == "--quiet" || a == "-q") g_quiet_mode = true;
    }
}

int cmd_version(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    constexpr int MAJOR = 1; constexpr int MINOR = 0; constexpr int PATCH = 0;
    if (g_json_mode) {
        util::JsonObject o;
        o["name"] = "btc-legacy";
        o["version"] = util::JsonValue(util::JsonArray{
            util::JsonValue(int64_t(MAJOR)),
            util::JsonValue(int64_t(MINOR)),
            util::JsonValue(int64_t(PATCH))
        });
        o["string"] = std::string("1.0.0");
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "btc-legacy 1.0.0\n"
                  << "Bitcoin Legacy Wallet CLI (2009–2015 wallet.dat tooling)\n"
                  << "Offline. No telemetry. No network access.\n";
    }
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
