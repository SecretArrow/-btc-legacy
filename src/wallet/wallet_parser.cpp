// src/wallet/wallet_parser.cpp
//
// Walk the BDB reader's records, classify each by prefix, and assemble
// a ParsedWallet view. We never discard unknown records — they're
// preserved in ParsedWallet::unknown_records so migrate() can decide
// what to do with them.
//
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_version.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/util/file_util.h"
#include <unordered_map>
#include <vector>
#include <map>

namespace btclegacy::wallet {

ParsedWallet::Compatibility classify(const ParsedWallet& w) {
    // No wallet prefix found at all
    bool any_wallet_record =
        w.record_counts.count("version") ||
        w.record_counts.count("key") ||
        w.record_counts.count("ckey") ||
        w.record_counts.count("mkey") ||
        w.record_counts.count("defaultkey") ||
        w.record_counts.count("name") ||
        w.record_counts.count("pool") ||
        w.record_counts.count("tx");
    if (!any_wallet_record) return ParsedWallet::Compatibility::UNSUPPORTED;

    // Encrypted wallet = has mkey AND ckey records
    if (w.record_counts.count("mkey") && w.record_counts.count("ckey")) {
        return ParsedWallet::Compatibility::LEGACY_BITCOIN_CORE;
    }
    // Pre-encryption wallet (Bitcoin 0.1.0 .. 0.3.x): key records only,
    // no mkey, no ckey.
    if (w.record_counts.count("key") && !w.record_counts.count("mkey")) {
        return ParsedWallet::Compatibility::EARLY_BITCOIN;
    }
    return ParsedWallet::Compatibility::UNKNOWN_LEGACY;
}

const char* compatibility_string(ParsedWallet::Compatibility c) {
    switch (c) {
        case ParsedWallet::Compatibility::EARLY_BITCOIN:        return "Early Bitcoin (unencrypted)";
        case ParsedWallet::Compatibility::LEGACY_BITCOIN_CORE:  return "Legacy Bitcoin Core (encrypted-capable)";
        case ParsedWallet::Compatibility::UNKNOWN_LEGACY:        return "Unknown legacy";
        case ParsedWallet::Compatibility::UNSUPPORTED:          return "Unsupported";
    }
    return "?";
}

bool parse_wallet(const std::string& path,
                  ParsedWallet& out,
                  std::string& err,
                  ParseStats* stats,
                  bool* is_bdb) {
    out = ParsedWallet{};
    if (!util::is_regular_file(path)) {
        err = "not a regular file: " + path;
        return false;
    }
    if (is_bdb) *is_bdb = false;

    bdb::Reader rd;
    if (!rd.open(path, err)) {
        // Could be a non-BDB file or a completely corrupted file
        return false;
    }
    if (is_bdb) *is_bdb = true;

    ParseStats st;
    auto cb = [&](const bdb::Record& rec) -> bool {
        st.records_seen++;
        std::string prefix;
        std::vector<uint8_t> suffix;
        if (!split_wallet_key(rec.key, prefix, suffix)) {
            st.errors++;
            return true;
        }
        out.record_counts[prefix]++;
        if (prefix == PREFIX_VERSION) {
            uint32_t v = 0;
            if (try_read_version(rec.value, v)) {
                out.wallet_version = v;
                st.records_parsed++;
            } else {
                out.warnings.push_back("malformed version record");
            }
        } else if (prefix == PREFIX_MKEY) {
            MasterKey mk = parse_master_key(rec.value);
            if (mk.valid) {
                out.master_keys.push_back(mk);
                out.mkey_count++;
                st.records_parsed++;
                out.has_master_key = true;
                out.encrypted = true;
            } else {
                st.errors++;
                out.errors.push_back("malformed mkey record: " + mk.error);
            }
        } else if (prefix == PREFIX_CKEY) {
            CryptedKeyRecord ck = parse_ckey_record(rec.value);
            if (ck.parsed_ok) {
                // Stash the suffix (CKeyID hash160) so that we can later
                // correlate ckey records with sibling "key" records.
                ck.vchPubKey = suffix; // best-effort correlation
                out.ckeys.push_back(std::move(ck));
                out.ckey_count++;
                st.records_parsed++;
                out.encrypted = true;
            } else {
                st.errors++;
                out.errors.push_back("malformed ckey record");
            }
        } else if (prefix == PREFIX_KEY) {
            KeyRecord kr = parse_key_record(rec.value);
            out.keys.push_back(std::move(kr));
            out.key_count++;
            st.records_parsed++;
        } else if (prefix == PREFIX_DEFAULTKEY) {
            out.defaultkey_present = true;
        } else if (prefix == PREFIX_POOL) {
            KeyPool p = parse_pool_record(rec.value);
            out.pool.push_back(std::move(p));
            out.pool_count++;
            st.records_parsed++;
        } else if (prefix == PREFIX_NAME) {
            // name record: the value is a UTF-8 label string
            std::string label(reinterpret_cast<const char*>(rec.value.data()), rec.value.size());
            out.names.emplace_back(util::to_hex(suffix), label);
            out.name_count++;
            st.records_parsed++;
        } else if (prefix == PREFIX_TX) {
            TxRecord tx = parse_tx_record(rec.value);
            out.txs.push_back(std::move(tx));
            out.tx_count++;
            st.records_parsed++;
        } else if (prefix == PREFIX_WATCHS) {
            out.watchonly_count++;
        } else if (prefix == PREFIX_HDCHAIN) {
            out.hd_chain_present = true;
        } else {
            // Unknown records — preserved, NOT silently discarded
            out.unknown_records.emplace_back(prefix, rec.value);
            st.unknown_records++;
        }
        return true;
    };
    std::string iterr;
    rd.for_each_record(cb, iterr, {});
    if (!iterr.empty()) {
        out.warnings.push_back(iterr);
    }

    // Classify compatibility
    out.compat = classify(out);

    // Sanity: if encrypted flag set on an early wallet, that's contradictory.
    if (out.encrypted && out.mkey_count == 0) {
        out.warnings.push_back("wallet reports encrypted records but has no master key");
    }
    if (stats) *stats = st;
    return true;
}

} // namespace btclegacy::wallet
