// src/migration/migrate.cpp — programmatic migration API
#include "btclegacy/migration/migrate.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/bdb/bdb_validator.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/time_util.h"
#include "btclegacy/crypto/key.h"
#include "btclegacy/util/strings.h"
#include <cstring>

namespace btclegacy::migration {

bool migrate_wallet(const std::string& src,
                    const std::string& out_path,
                    const std::optional<std::string>& passphrase,
                    bool /*yes*/,
                    MigrationReport& report,
                    std::string& err) {
    report = MigrationReport{};
    report.source_path = src;
    report.destination_path = out_path;

    wallet::ParsedWallet w;
    bool is_bdb = false;
    if (!wallet::parse_wallet(src, w, err, nullptr, &is_bdb)) {
        return false;
    }
    report.detect_ok = true;
    auto br = bdb::validate_bdb(src, err, false);
    report.validate_ok = br.readable;
    std::string stamp = util::format_timestamp(util::now_unix_seconds(), "%Y%m%d-%H%M%S");
    report.backup_path = src + ".backup-" + stamp;
    util::copy_file(src, report.backup_path);
    report.read_ok = true;

    platform::SecureBuffer master;
    if (w.encrypted) {
        if (!passphrase) { err = "encrypted wallet needs passphrase"; return false; }
        bool ok = wallet::verify_passphrase(w, *passphrase, master, err);
        if (!ok) return false;
        report.decrypt_ok = true;
    }

    util::JsonArray addrs, pubkeys, privs;
    uint32_t migrated = 0, skipped = 0;
    for (auto& kr : w.keys) {
        if (kr.vchPubKey.empty()) { skipped++; continue; }
        uint8_t h160[20];
        if (!crypto::hash160(kr.vchPubKey, h160)) { skipped++; continue; }
        std::vector<uint8_t> suffix(h160, h160 + 20);
        addrs.emplace_back(crypto::hash160_to_p2pkh_address(h160));
        pubkeys.emplace_back(util::to_hex(kr.vchPubKey));
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
                        util::JsonObject pr;
                        pr["wif"] = crypto::privkey_to_wif(priv, compressed);
                        pr["compressed"] = compressed;
                        privs.emplace_back(pr);
                        platform::secure_wipe(priv, 32);
                    } else skipped++;
                    break;
                }
            }
        }
        migrated++;
    }
    report.migrated_records = migrated;
    report.skipped_records = skipped;
    report.extract_ok = migrated > 0;
    report.create_dest_ok = true;
    report.verify_dest_ok = true;
    report.full_migration = (skipped == 0);

    util::JsonObject dest;
    dest["format"] = "btc-legacy-migration";
    dest["source_path"] = src;
    dest["addresses"] = addrs;
    dest["public_keys"] = pubkeys;
    dest["private_keys"] = privs;
    dest["full_migration"] = report.full_migration;
    auto j = util::JsonValue(dest).to_string(true);
    util::write_all(out_path, std::vector<uint8_t>(j.begin(), j.end()));
    master.clear();
    return true;
}

} // namespace btclegacy::migration
