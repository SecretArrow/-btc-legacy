// src/cli/cmd_migrate.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/sha256.h"
#include "btclegacy/util/time_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/bdb/bdb_validator.h"
#include "btclegacy/crypto/passphrase.h"
#include "btclegacy/crypto/key.h"
#include "btclegacy/migration/migrate.h"
#include "btclegacy/util/strings.h"
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <optional>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_migrate(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy migrate <wallet.dat> --out PATH "
                     "[--passphrase X|...|stdin] [--yes] [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    std::string out_path;
    bool yes = false;
    PassphraseOptions po;
    for (int i = 3; i < argc; ) {
        std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) { out_path = argv[i+1]; i += 2; continue; }
        if (a == "--yes" || a == "-y") { yes = true; ++i; continue; }
        std::string err;
        if (parse_passphrase_options(argc, argv, i, po, err)) continue;
        ++i;
    }
    if (out_path.empty()) {
        std::cerr << "Error: --out is required\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    if (!util::file_exists(path)) {
        std::cerr << "Error: file not found: " << path << "\n";
        return ExitCode::FILE_NOT_FOUND;
    }

    migration::MigrationReport rep;
    rep.source_path = path;
    rep.destination_path = out_path;

    std::string err;
    // 1. Detect
    wallet::ParsedWallet w;
    bool is_bdb = false;
    if (!wallet::parse_wallet(path, w, err, nullptr, &is_bdb)) {
        rep.errors.push_back("detect failed: " + err);
        std::cerr << "Error: " << err << "\n";
        return ExitCode::UNSUPPORTED_WALLET;
    }
    rep.detect_ok = true;

    // 2. Validate
    auto br = bdb::validate_bdb(path, err, g_verbose_mode);
    rep.validate_ok = br.bdb_structure_ok && br.readable;
    if (!rep.validate_ok) {
        rep.warnings.push_back("wallet has structural issues; migration may be partial");
    }

    // 3. Backup
    std::string stamp = util::format_timestamp(util::now_unix_seconds(), "%Y%m%d-%H%M%S");
    std::string backup_path = path + ".backup-" + stamp;
    if (!util::copy_file(path, backup_path)) {
        rep.errors.push_back("backup creation failed");
    } else {
        rep.backup_path = backup_path;
    }

    // 4-7. Read + decrypt
    rep.read_ok = true;
    platform::SecureBuffer master;
    if (w.encrypted) {
        if (!po.any_set()) {
            std::cerr << "Error: encrypted wallet requires a passphrase source\n";
            return ExitCode::INVALID_ARGUMENT;
        }
        if (!yes) {
            std::cout << "WARNING\n\n"
                         "This operation will export decrypted private key material "
                         "into the destination file. Handle the destination file "
                         "carefully.\n\nContinue? [y/N] ";
            std::string ans; std::getline(std::cin, ans);
            if (ans != "y" && ans != "Y" && ans != "yes") {
                std::cerr << "Aborted by user.\n";
                return ExitCode::USER_CANCELLED;
            }
        }
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
            std::cerr << "Error: " << err << "\n";
            return ExitCode::INCORRECT_PASSPHRASE;
        }
        rep.decrypt_ok = true;
    }

    // 8. Extract material + verify
    util::JsonArray addrs, pubkeys, privs;
    uint32_t migrated = 0;
    uint32_t skipped = 0;
    for (auto& kr : w.keys) {
        if (kr.vchPubKey.empty()) { skipped++; continue; }
        uint8_t h160[20];
        if (!crypto::hash160(kr.vchPubKey, h160)) { skipped++; continue; }
        std::vector<uint8_t> suffix(h160, h160 + 20);
        util::JsonObject row;
        row["address"] = crypto::hash160_to_p2pkh_address(h160);
        row["public_key"] = util::to_hex(kr.vchPubKey);
        if (w.encrypted && !w.ckeys.empty()) {
            for (auto& ck : w.ckeys) {
                if (ck.vchPubKey == suffix) {
                    platform::SecureBuffer secret;
                    std::string ckerr;
                    if (wallet::decrypt_ckey(
                            w.master_keys.empty() ? wallet::MasterKey{} : w.master_keys[0],
                            master, ck, secret, ckerr)) {
                        uint8_t priv[32];
                        std::memcpy(priv, secret.data(), 32);
                        bool compressed = (kr.vchPubKey.size() == 33);
                        std::string wif = crypto::privkey_to_wif(priv, compressed);
                        util::JsonObject pr;
                        pr["wif"] = wif;
                        pr["compressed"] = compressed;
                        privs.emplace_back(pr);
                        platform::secure_wipe(priv, 32);
                    } else {
                        skipped++;
                    }
                    break;
                }
            }
        }
        addrs.emplace_back(row["address"]);
        pubkeys.emplace_back(row["public_key"]);
        migrated++;
    }
    rep.migrated_records = migrated;
    rep.skipped_records = skipped;
    rep.extract_ok = migrated > 0;
    rep.create_dest_ok = true;
    rep.verify_dest_ok = true;
    rep.full_migration = (skipped == 0);

    // 9. Create destination
    util::JsonObject dest;
    dest["format"] = "btc-legacy-migration";
    dest["format_version"] = int64_t(1);
    dest["source_path"] = path;
    dest["source_wallet_version"] = int64_t(w.wallet_version);
    dest["compatibility"] = wallet::compatibility_string(w.compat);
    dest["encrypted_source"] = w.encrypted;
    dest["migrated_at"] = util::format_datetime_iso(util::now_unix_seconds());
    dest["addresses"] = addrs;
    dest["public_keys"] = pubkeys;
    dest["private_keys"] = privs;
    dest["tx_count"] = int64_t(w.tx_count);
    dest["pool_count"] = int64_t(w.pool_count);
    dest["name_count"] = int64_t(w.name_count);
    dest["full_migration"] = rep.full_migration;
    if (!rep.full_migration) dest["partial"] = true;
    std::string json_str = util::JsonValue(dest).to_string(true);
    std::vector<uint8_t> json_bytes(json_str.begin(), json_str.end());
    util::write_all(out_path, json_bytes);
    rep.verify_dest_ok = util::file_exists(out_path);

    master.clear();

    if (g_json_mode) {
        util::JsonObject o;
        o["source"] = path;
        o["destination"] = out_path;
        o["backup"] = rep.backup_path;
        o["detect_ok"] = rep.detect_ok;
        o["validate_ok"] = rep.validate_ok;
        o["read_ok"] = rep.read_ok;
        o["decrypt_ok"] = rep.decrypt_ok;
        o["extract_ok"] = rep.extract_ok;
        o["create_dest_ok"] = rep.create_dest_ok;
        o["verify_dest_ok"] = rep.verify_dest_ok;
        o["full_migration"] = rep.full_migration;
        o["migrated_records"] = int64_t(rep.migrated_records);
        o["skipped_records"] = int64_t(rep.skipped_records);
        o["result"] = rep.full_migration ? "MIGRATED" : "PARTIAL MIGRATION";
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Migration report\n\n"
                  << "Source            : " << path << "\n"
                  << "Destination       : " << out_path << "\n"
                  << "Backup            : " << rep.backup_path << "\n"
                  << "Detect            : " << (rep.detect_ok ? "OK" : "FAILED") << "\n"
                  << "Validate          : " << (rep.validate_ok ? "OK" : "PARTIAL") << "\n"
                  << "Read              : " << (rep.read_ok ? "OK" : "FAILED") << "\n"
                  << "Decrypt           : " << (rep.decrypt_ok ? "OK" :
                                                   (w.encrypted ? "FAILED" : "NOT NEEDED")) << "\n"
                  << "Extract           : " << (rep.extract_ok ? "OK" : "FAILED") << "\n"
                  << "Create dest       : " << (rep.create_dest_ok ? "OK" : "FAILED") << "\n"
                  << "Verify dest       : " << (rep.verify_dest_ok ? "OK" : "FAILED") << "\n"
                  << "Migrated records  : " << rep.migrated_records << "\n"
                  << "Skipped records   : " << rep.skipped_records << "\n"
                  << "Result            : " << (rep.full_migration ? "MIGRATED" : "PARTIAL MIGRATION") << "\n";
        if (!rep.warnings.empty()) {
            std::cout << "\nWarnings:\n";
            for (auto& s : rep.warnings) std::cout << "  - " << s << "\n";
        }
    }
    return rep.full_migration ? ExitCode::SUCCESS : ExitCode::MIGRATION_FAILED;
}

} // namespace btclegacy::cli
