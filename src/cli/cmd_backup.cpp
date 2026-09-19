// src/cli/cmd_backup.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/sha256.h"
#include "btclegacy/util/time_util.h"
#include <iostream>
#include <cstring>
#include <string>
#include <fstream>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_backup(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy backup <wallet.dat> [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    if (!util::file_exists(path)) {
        std::cerr << "Error: file not found: " << path << "\n";
        return ExitCode::FILE_NOT_FOUND;
    }
    std::string stamp = util::format_timestamp(util::now_unix_seconds(), "%Y%m%d-%H%M%S");
    std::string backup_path = path + ".backup-" + stamp;
    if (!g_json_mode) std::cout << "Creating backup...\n\n";
    if (!util::copy_file(path, backup_path)) {
        std::cerr << "Error: backup copy failed\n";
        return ExitCode::PERMISSION_ERROR;
    }
    // Verify SHA-256
    std::string src_sha = util::sha256_hex_file(path);
    std::string bak_sha = util::sha256_hex_file(backup_path);
    bool ok = !src_sha.empty() && src_sha == bak_sha;
    if (g_json_mode) {
        util::JsonObject o;
        o["source"] = path;
        o["backup"] = backup_path;
        o["source_sha256"] = src_sha;
        o["backup_sha256"] = bak_sha;
        o["verification"] = ok ? "OK" : "MISMATCH";
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Source : " << path << "\n"
                  << "Backup : " << backup_path << "\n\n"
                  << "SHA-256 source : " << src_sha << "\n"
                  << "SHA-256 backup : " << bak_sha << "\n\n"
                  << "Verification: " << (ok ? "OK" : "MISMATCH") << "\n";
    }
    return ok ? ExitCode::SUCCESS : ExitCode::CORRUPTED_WALLET;
}

} // namespace btclegacy::cli
