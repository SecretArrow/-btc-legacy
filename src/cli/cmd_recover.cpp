// src/cli/cmd_recover.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/sha256.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/bdb/bdb_reader.h"
#include "btclegacy/bdb/bdb_validator.h"
#include "btclegacy/crypto/passphrase.h"
#include "btclegacy/recovery/recover.h"
#include <iostream>
#include <cstring>
#include <string>
#include <optional>
#include <vector>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_recover(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy recover <wallet.dat> "
                     "[--passphrase X|...|stdin] [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    if (!util::file_exists(path)) {
        std::cerr << "Error: file not found: " << path << "\n";
        return ExitCode::FILE_NOT_FOUND;
    }
    PassphraseOptions po;
    for (int i = 3; i < argc; ) {
        std::string err;
        if (parse_passphrase_options(argc, argv, i, po, err)) continue;
        ++i;
    }
    std::string err;
    bdb::ValidationReport br = bdb::validate_bdb(path, err, g_verbose_mode);

    // First parse the wallet for parsed records
    wallet::ParsedWallet w;
    bool is_bdb = false;
    bool parsed_ok = wallet::parse_wallet(path, w, err, nullptr, &is_bdb);

    // Decrypt ckeys if passphrase supplied
    platform::SecureBuffer master;
    if (po.any_set() && w.encrypted && parsed_ok) {
        crypto::PassphraseRequest pr;
        pr.has_passphrase_arg = po.has_arg; pr.passphrase_arg = po.arg;
        pr.has_passphrase_file = po.has_file; pr.passphrase_file = po.file;
        pr.passphrase_stdin = po.stdin_flag;
        platform::SecureBuffer pp_buf;
        std::string acq_err;
        if (!crypto::acquire_passphrase(pr, pp_buf, acq_err)) {
            std::cerr << "Error: " << acq_err << "\n";
            return ExitCode::GENERAL_ERROR;
        }
        std::string pp = pp_buf.as_string();
        pp_buf.clear();
        bool ok = wallet::verify_passphrase(w, pp, master, err);
        platform::secure_wipe(&pp[0], pp.size());
        if (!ok) {
            if (g_json_mode) {
                util::JsonObject o; o["error"] = err;
                std::cout << util::JsonValue(o).to_string() << "\n";
            } else {
                std::cerr << "Error: " << err << "\n";
            }
            return ExitCode::INCORRECT_PASSPHRASE;
        }
    }

    recovery::RecoveryReport r;
    r.bdb_readable = br.readable;
    r.wallet_records_present = parsed_ok;
    r.wallet_records_full = (br.corrupt_pages == 0);
    r.master_key_present = !w.master_keys.empty();
    r.encrypted_keys_present = !w.ckeys.empty();
    r.total_records = uint32_t(br.records);
    r.recovered_records = uint32_t(br.records - br.corrupt_pages);
    r.corrupted_records = br.corrupt_pages;
    r.pages_read = br.total_pages;
    r.pages_with_errors = br.corrupt_pages;
    if (br.corrupt_pages == 0) r.result = recovery::RecoveryReport::Result::OK;
    else if (br.records > 0) r.result = recovery::RecoveryReport::Result::PARTIALLY_RECOVERABLE;
    else r.result = recovery::RecoveryReport::Result::UNRECOVERABLE;
    for (auto& s : br.warnings) r.warnings.push_back(s);

    if (g_json_mode) {
        util::JsonObject o;
        o["wallet"] = path;
        o["bdb_readable"] = r.bdb_readable;
        o["wallet_records_present"] = r.wallet_records_present;
        o["wallet_records_full"] = r.wallet_records_full;
        o["master_key_present"] = r.master_key_present;
        o["encrypted_keys_present"] = r.encrypted_keys_present;
        o["total_records"] = int64_t(r.total_records);
        o["recovered_records"] = int64_t(r.recovered_records);
        o["corrupted_records"] = int64_t(r.corrupted_records);
        o["pages_read"] = int64_t(r.pages_read);
        o["pages_with_errors"] = int64_t(r.pages_with_errors);
        o["result"] = r.result == recovery::RecoveryReport::Result::OK ? "OK" :
                       r.result == recovery::RecoveryReport::Result::PARTIALLY_RECOVERABLE ?
                       "PARTIALLY_RECOVERABLE" : "UNRECOVERABLE";
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Recovery analysis\n\n";
        std::cout << "BDB readable          : " << (r.bdb_readable ? "YES" : "NO") << "\n";
        std::cout << "Wallet records        : " << (r.wallet_records_present ?
                       (r.wallet_records_full ? "FULL" : "PARTIAL") : "NONE") << "\n";
        std::cout << "Master key            : " << (r.master_key_present ? "PRESENT" : "ABSENT") << "\n";
        std::cout << "Encrypted keys        : " << r.encrypted_keys_present << "\n";
        std::cout << "Transactions          : " << w.tx_count << "\n";
        std::cout << "Corrupted records     : " << r.corrupted_records << "\n";
        std::cout << "\nResult: "
                  << (r.result == recovery::RecoveryReport::Result::OK ? "OK" :
                      r.result == recovery::RecoveryReport::Result::PARTIALLY_RECOVERABLE ?
                      "PARTIALLY RECOVERABLE" : "UNRECOVERABLE")
                  << "\n";
        if (!r.warnings.empty()) {
            std::cout << "\nWarnings:\n";
            for (auto& s : r.warnings) std::cout << "  - " << s << "\n";
        }
    }
    master.clear();
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
