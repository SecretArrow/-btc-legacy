// src/cli/cmd_password.cpp
//
// Implements `btc-legacy password verify <wallet> [PASSPHRASE SOURCE]`.
//
// The passphrase is acquired via crypto::acquire_passphrase, then
// verified against the wallet's actual encryption metadata by
// wallet::verify_passphrase.
//
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/crypto/passphrase.h"
#include <iostream>
#include <cstring>
#include <string>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_password(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    // Expect: btc-legacy password verify <wallet> [PASSPHRASE SOURCE]
    if (argc < 4 || std::strcmp(argv[2], "verify") != 0) {
        std::cerr << "Usage: btc-legacy password verify <wallet.dat> "
                     "[--passphrase X | --passphrase-file PATH | --passphrase-stdin] "
                     "[--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[3];
    if (!util::file_exists(path)) {
        std::cerr << "Error: file not found: " << path << "\n";
        return ExitCode::FILE_NOT_FOUND;
    }
    // Collect passphrase source options
    PassphraseOptions po;
    for (int i = 4; i < argc; ) {
        std::string err;
        if (parse_passphrase_options(argc, argv, i, po, err)) continue;
        // Otherwise: skip unknown flag (could be --json which was already
        // consumed by the global pre-pass)
        ++i;
    }
    // Parse the wallet first (read-only)
    std::string err;
    wallet::ParsedWallet w;
    bool is_bdb = false;
    if (!wallet::parse_wallet(path, w, err, nullptr, &is_bdb)) {
        std::cerr << "Error: " << err << "\n";
        return ExitCode::UNSUPPORTED_WALLET;
    }
    if (!w.encrypted) {
        if (g_json_mode) {
            util::JsonObject o;
            o["wallet"] = path;
            o["encrypted"] = false;
            o["result"] = "success";
            o["note"] = "wallet is not encrypted";
            std::cout << util::JsonValue(o).to_string() << "\n";
        } else {
            std::cout << "Wallet       : " << path << "\n"
                      << "Encrypted    : NO\n"
                      << "Verification : SUCCESS (no passphrase required)\n";
        }
        return ExitCode::SUCCESS;
    }
    // Acquire the passphrase
    crypto::PassphraseRequest pr;
    pr.has_passphrase_arg = po.has_arg;
    pr.passphrase_arg      = po.arg;
    pr.has_passphrase_file = po.has_file;
    pr.passphrase_file     = po.file;
    pr.passphrase_stdin    = po.stdin_flag;
    pr.prompt_text         = "Enter wallet passphrase:";

    platform::SecureBuffer passphrase_buf;
    std::string acq_err;
    if (!crypto::acquire_passphrase(pr, passphrase_buf, acq_err)) {
        std::cerr << "Error: " << acq_err << "\n";
        return ExitCode::GENERAL_ERROR;
    }
    std::string passphrase = passphrase_buf.as_string();
    // Wipe the SecureBuffer copy — passphrase (std::string) is wiped
    // AFTER verification below.
    passphrase_buf.clear();

    platform::SecureBuffer derived_master;
    bool ok = wallet::verify_passphrase(w, passphrase, derived_master, err);
    platform::secure_wipe(&passphrase[0], passphrase.size());

    if (g_json_mode) {
        util::JsonObject o;
        o["wallet"] = path;
        o["encrypted"] = true;
        o["passphrase_valid"] = ok;
        o["result"] = ok ? "success" : "failed";
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Wallet       : " << path << "\n"
                  << "Encrypted    : YES\n"
                  << "Passphrase   : " << (ok ? "CORRECT" : "INCORRECT") << "\n"
                  << "Verification : " << (ok ? "SUCCESS" : "FAILED") << "\n";
    }
    return ok ? ExitCode::SUCCESS : ExitCode::INCORRECT_PASSPHRASE;
}

} // namespace btclegacy::cli
