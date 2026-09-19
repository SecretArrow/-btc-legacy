// src/cli/cmd_export.cpp
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/crypto/passphrase.h"
#include "btclegacy/crypto/key.h"
#include <iostream>
#include <cstring>
#include <string>
#include <vector>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_export(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr << "Usage: btc-legacy export <wallet.dat> "
                     "[--addresses] [--public-keys] [--transactions] "
                     "[--private-keys] [--passphrase X|...|stdin] [--yes] [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
    bool export_addresses = false;
    bool export_pubkeys = false;
    bool export_txs = false;
    bool export_privkeys = false;
    bool yes = false;
    PassphraseOptions po;
    for (int i = 3; i < argc; ) {
        std::string a = argv[i];
        if (a == "--addresses") { export_addresses = true; ++i; continue; }
        if (a == "--public-keys") { export_pubkeys = true; ++i; continue; }
        if (a == "--transactions") { export_txs = true; ++i; continue; }
        if (a == "--private-keys") { export_privkeys = true; ++i; continue; }
        if (a == "--yes" || a == "-y") { yes = true; ++i; continue; }
        std::string err;
        if (parse_passphrase_options(argc, argv, i, po, err)) continue;
        ++i; // skip unknown
    }
    if (!(export_addresses || export_pubkeys || export_txs || export_privkeys)) {
        export_addresses = true; // default
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
    platform::SecureBuffer master_key;
    if (export_privkeys) {
        if (!w.encrypted) {
            std::cerr << "Error: --private-keys requested but wallet is not "
                         "encrypted — early Bitcoin wallets without a ckey/mkey "
                         "record are NOT supported for private-key export by "
                         "this tool. Use --public-keys instead.\n";
            return ExitCode::UNSUPPORTED_WALLET;
        }
        if (!po.any_set()) {
            std::cerr << "Error: --private-keys requires a passphrase source "
                         "(--passphrase / --passphrase-file / --passphrase-stdin "
                         "or interactive prompt).\n";
            return ExitCode::INVALID_ARGUMENT;
        }
        // Confirm
        if (!yes) {
            std::cout <<
                "WARNING\n\n"
                "This operation will export private keys.\n\n"
                "Private keys provide control over the associated Bitcoin.\n\n"
                "Continue? [y/N] ";
            std::string ans;
            std::getline(std::cin, ans);
            if (ans != "y" && ans != "Y" && ans != "yes") {
                std::cerr << "Aborted by user.\n";
                return ExitCode::USER_CANCELLED;
            }
        }
        // Acquire passphrase and verify
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
        bool ok = wallet::verify_passphrase(w, pp, master_key, err);
        platform::secure_wipe(&pp[0], pp.size());
        if (!ok) {
            std::cerr << "Error: " << err << "\n";
            return ExitCode::INCORRECT_PASSPHRASE;
        }
    }

    // Build output rows.
    // Each row corresponds to one "key" record (and possibly its
    // encrypted sibling "ckey" record).
    if (g_json_mode) {
        util::JsonArray out_arr;
        for (auto& kr : w.keys) {
            // Match against ckey records: historical Bitcoin stores a
            // ckey record keyed by hash160(pubkey), with the IV-prefixed
            // ciphertext as the value. Since we captured the hash160
            // suffix in the ckey record's vchPubKey field at parse time,
            // we match by looking at the corresponding key's pubkey and
            // comparing suffixes.
            std::vector<uint8_t> pub = kr.vchPubKey;
            if (pub.empty()) continue;
            uint8_t h160[20];
            if (!crypto::hash160(pub, h160)) continue;
            std::vector<uint8_t> suffix(h160, h160 + 20);
            util::JsonObject row;
            std::string pub_hex = util::to_hex(pub);
            if (export_pubkeys) row["public_key"] = pub_hex;
            if (export_addresses) {
                row["address"] = crypto::hash160_to_p2pkh_address(h160);
            }
            if (export_privkeys && !w.ckeys.empty()) {
                // Find the matching ckey by suffix
                for (auto& ck : w.ckeys) {
                    if (ck.vchPubKey == suffix) {
                        platform::SecureBuffer secret;
                        std::string ckerr;
                        if (wallet::decrypt_ckey(w.master_keys.empty() ? wallet::MasterKey{} : w.master_keys[0],
                                                  master_key, ck, secret, ckerr)) {
                            uint8_t priv[32];
                            std::memcpy(priv, secret.data(), 32);
                            bool compressed = (pub.size() == 33);
                            std::string wif = crypto::privkey_to_wif(priv, compressed);
                            row["wif"] = wif;
                            platform::secure_wipe(priv, 32);
                        }
                        break;
                    }
                }
            }
            out_arr.emplace_back(row);
        }
        util::JsonObject root;
        root["wallet"] = path;
        root["exported"] = out_arr;
        std::cout << util::JsonValue(root).to_string() << "\n";
    } else {
        std::cout << "Bitcoin Legacy Wallet Export\n\n";
        if (export_addresses) std::cout << "[Addresses]\n";
        for (auto& kr : w.keys) {
            if (kr.vchPubKey.empty()) continue;
            uint8_t h160[20];
            if (!crypto::hash160(kr.vchPubKey, h160)) continue;
            std::string addr = crypto::hash160_to_p2pkh_address(h160);
            std::cout << addr;
            if (export_pubkeys) std::cout << "  " << util::to_hex(kr.vchPubKey);
            if (export_privkeys) {
                std::vector<uint8_t> suffix(h160, h160 + 20);
                for (auto& ck : w.ckeys) {
                    if (ck.vchPubKey == suffix) {
                        platform::SecureBuffer secret;
                        std::string ckerr;
                        if (wallet::decrypt_ckey(w.master_keys.empty() ? wallet::MasterKey{} : w.master_keys[0],
                                                  master_key, ck, secret, ckerr)) {
                            uint8_t priv[32];
                            std::memcpy(priv, secret.data(), 32);
                            bool compressed = (kr.vchPubKey.size() == 33);
                            std::string wif = crypto::privkey_to_wif(priv, compressed);
                            std::cout << "  " << wif;
                            platform::secure_wipe(priv, 32);
                        }
                        break;
                    }
                }
            }
            std::cout << "\n";
        }
        if (export_txs && !w.txs.empty()) {
            std::cout << "\n[Transactions]\n";
            for (auto& tx : w.txs) {
                std::cout << "  tx (raw bytes: " << tx.vchTxData.size() << ")\n";
            }
        }
    }
    master_key.clear();
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
