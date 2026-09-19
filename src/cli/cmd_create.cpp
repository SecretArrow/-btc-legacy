// src/cli/cmd_create.cpp
//
// Create synthetic, year-accurate legacy Bitcoin-compatible test wallet
// fixtures. The wallets are designed to exercise our own reader and
// the wallet parser, NOT to fool any real Bitcoin Core client.
//
// Year → profile:
//
//   2009 — Pre-0.3 (no version record, no encryption, uncompressed
//                   pubkeys, only key+name+defaultkey+pool+tx records)
//   2010 — 0.3.x (version=10500, uncompressed pubkeys, no encryption)
//   2011 — 0.3.2x-0.4.0 (version=40000, encryption-capable flag still off)
//   2012 — 0.4.x/0.5.0 encrypted wallets appear; --encrypted works here
//   2013 — 0.7.x/0.8.x (version=60000, compressed pubkeys, --encrypted works)
//   2014 — 0.9.x (version=60000, compressed pubkeys)
//   2015 — 0.10.x/0.11.x (version=60000, compressed pubkeys, more metadata)
//
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/json_writer.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/util/sha256.h"
#include "btclegacy/bdb/bdb_writer.h"
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/crypto/key.h"
#include "btclegacy/parser/serializer.h"
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include <map>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

namespace {

struct CreateArgs {
    int year = 2012;
    std::string out_path;
    bool encrypted = false;
    std::string passphrase;
    int  keys = 8;
    uint64_t seed = 0; // 0 = use cryptographic random
    bool testnet = false;
};

bool parse_args(int argc, char** argv, CreateArgs& a, std::string& err) {
    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&]() -> std::optional<std::string> {
            if (i + 1 >= argc) return std::nullopt;
            return std::string(argv[++i]);
        };
        if (s == "--year") {
            auto v = next(); if (!v) { err = "--year needs value"; return false; }
            a.year = std::atoi(v->c_str());
            if (a.year < 2009 || a.year > 2015) {
                err = "--year must be in [2009..2015]";
                return false;
            }
        } else if (s == "--out") {
            auto v = next(); if (!v) { err = "--out needs value"; return false; }
            a.out_path = *v;
        } else if (s == "--encrypted") {
            a.encrypted = true;
        } else if (s == "--passphrase") {
            auto v = next(); if (!v) { err = "--passphrase needs value"; return false; }
            a.passphrase = *v;
            a.encrypted = true; // --passphrase implies --encrypted
        } else if (s == "--keys") {
            auto v = next(); if (!v) { err = "--keys needs value"; return false; }
            a.keys = std::atoi(v->c_str());
        } else if (s == "--seed") {
            auto v = next(); if (!v) { err = "--seed needs value"; return false; }
            a.seed = std::stoull(*v);
        } else if (s == "--testnet") {
            a.testnet = true;
        }
    }
    if (a.out_path.empty()) { err = "--out is required"; return false; }
    if (a.encrypted && a.passphrase.empty()) {
        err = "--encrypted requires --passphrase";
        return false;
    }
    return true;
}

// Determine the compressed-flag for the given year.
// Pre-2012 wallets used uncompressed pubkeys (65 bytes); 2012+ switched
// to compressed (33 bytes). Some pre-2012 wallets contain a mix, but
// our synthetic fixtures pick one form per wallet.
bool use_compressed_for_year(int year) {
    // Bitcoin Core switched the default to compressed pubkeys in 0.6.0 (March 2012)
    return year >= 2012;
}

// Pick a wallet_version value consistent with the year.
uint32_t version_for_year(int year) {
    switch (year) {
        case 2009: return 0;        // no version record (pre-0.3.0 Bitcoin)
        case 2010: return 10500;     // 0.5.x baseline wallet feature
        case 2011: return 40000;     // encryption-capable
        case 2012: return 60000;     // 0.6.0 — compressed pubkeys
        case 2013: return 60000;
        case 2014: return 60000;
        case 2015: return 60000;
        default:  return 60000;
    }
}

// Generate `n` private keys + their corresponding pubkeys. Uses
// OpenSSL RAND_bytes by default; deterministic if a seed is supplied.
bool generate_keys(int n, uint64_t seed, bool compressed,
                   std::vector<std::vector<uint8_t>>& privkeys,
                   std::vector<std::vector<uint8_t>>& pubkeys) {
    privkeys.clear(); pubkeys.clear();
    privkeys.reserve(n); pubkeys.reserve(n);

    // If a deterministic seed is requested, use it as the initial RNG state.
    // We use RAND_bytes for real keys, but for fixture-reproducibility we
    // XOR the seed into a SHA-256 counter to derive deterministic bytes.
    auto fill_priv = [&](uint8_t out[32], int idx) -> bool {
        if (seed != 0) {
            uint8_t counter[16] = {0};
            for (int i = 0; i < 8; ++i) counter[i] = uint8_t((seed >> (i*8)) & 0xff);
            for (int i = 8; i < 16; ++i) counter[i] = uint8_t((idx >> ((i-8)*8)) & 0xff);
            // SHA-256(counter + idx) — use our own Sha256
            util::Sha256 h;
            h.update(counter, 16);
            uint8_t bytes[32];
            h.finish(bytes);
            // Ensure the key is in valid range by reducing modulo (n-1) — but
            // for fixture purposes, if invalid we just keep retrying with idx+1
            // up to a small number of attempts.
            std::memcpy(out, bytes, 32);
            return true;
        }
        return crypto::random_bytes(out, 32);
    };

    for (int i = 0; i < n; ++i) {
        uint8_t priv[32];
        // Generate and validate
        for (int attempt = 0; attempt < 16; ++attempt) {
            if (!fill_priv(priv, i + attempt)) return false;
            if (crypto::is_valid_privkey(priv)) break;
        }
        if (!crypto::is_valid_privkey(priv)) return false;

        std::vector<uint8_t> pub;
        if (!crypto::privkey_to_pubkey(priv, compressed, pub)) return false;
        privkeys.emplace_back(priv, priv + 32);
        pubkeys.push_back(pub);
    }
    return true;
}

// Build the BDB records list for a synthetic wallet.
bool build_records(const CreateArgs& a,
                   std::vector<bdb::WriteRecord>& out_records,
                   std::vector<uint8_t>& out_default_key,
                   std::string& err) {
    bool compressed = use_compressed_for_year(a.year);
    uint32_t wallet_ver = version_for_year(a.year);

    std::vector<std::vector<uint8_t>> privkeys, pubkeys;
    if (!generate_keys(a.keys, a.seed, compressed, privkeys, pubkeys)) {
        err = "key generation failed";
        return false;
    }
    if (pubkeys.empty()) { err = "no keys generated"; return false; }

    // version record
    if (wallet_ver != 0) {
        std::vector<uint8_t> v(4);
        v[0] = uint8_t(wallet_ver & 0xff);
        v[1] = uint8_t((wallet_ver >> 8) & 0xff);
        v[2] = uint8_t((wallet_ver >> 16) & 0xff);
        v[3] = uint8_t((wallet_ver >> 24) & 0xff);
        bdb::WriteRecord wr;
        wr.key.assign(wallet::PREFIX_VERSION, wallet::PREFIX_VERSION + std::strlen(wallet::PREFIX_VERSION));
        wr.value = v;
        out_records.push_back(std::move(wr));
    }

    // defaultkey record (the first generated key's pubkey)
    out_default_key = pubkeys[0];
    {
        bdb::WriteRecord wr;
        wr.key.assign(wallet::PREFIX_DEFAULTKEY, wallet::PREFIX_DEFAULTKEY + std::strlen(wallet::PREFIX_DEFAULTKEY));
        wr.value = out_default_key;
        out_records.push_back(std::move(wr));
    }

    // For each key, write a "key" record keyed by hash160(pubkey).
    // In an encrypted wallet, also write a "ckey" record per key.
    // We also write a "name" record per key (label "Address NN").
    platform::SecureBuffer master_key;
    wallet::MasterKey mk;
    bool have_master = false;
    if (a.encrypted) {
        if (!wallet::build_master_key_for_passphrase(a.passphrase, mk, master_key)) {
            err = "failed to build master key";
            return false;
        }
        have_master = true;
        // Write the mkey record (key prefix is "mkey" + uint32 id)
        bdb::WriteRecord wr;
        wr.key.assign(wallet::PREFIX_MKEY, wallet::PREFIX_MKEY + std::strlen(wallet::PREFIX_MKEY));
        wr.key.push_back(0); wr.key.push_back(0); wr.key.push_back(0); wr.key.push_back(1); // id=1
        // Serialize MasterKey: vchCryptedKey(varint+bytes), vchSalt(varint+bytes), nDerivationMethod(4), nDeriveCount(4)
        parser::Serializer s;
        s.put_bytes_prefixed(mk.vchCryptedKey);
        s.put_bytes_prefixed(mk.vchSalt);
        s.put_u32(mk.nDerivationMethod);
        s.put_u32(mk.nDeriveCount);
        wr.value = s.take();
        out_records.push_back(std::move(wr));
    }

    for (size_t i = 0; i < pubkeys.size(); ++i) {
        // Compute hash160(pubkey)
        uint8_t h160[20];
        if (!crypto::hash160(pubkeys[i], h160)) {
            err = "hash160 failed";
            return false;
        }
        // key record
        bdb::WriteRecord wr_key;
        wr_key.key.assign(wallet::PREFIX_KEY, wallet::PREFIX_KEY + std::strlen(wallet::PREFIX_KEY));
        wr_key.key.insert(wr_key.key.end(), h160, h160 + 20);
        // Value: pubkey + nTime(int64) + vchKeyMeta(varint+bytes)
        parser::Serializer sk;
        sk.put_bytes_prefixed(pubkeys[i]);
        sk.put_i64(int64_t(1234567890LL + i)); // deterministic timestamp
        sk.put_bytes_prefixed({});
        wr_key.value = sk.take();
        out_records.push_back(std::move(wr_key));

        // name record (label for this address)
        bdb::WriteRecord wr_name;
        wr_name.key.assign(wallet::PREFIX_NAME, wallet::PREFIX_NAME + std::strlen(wallet::PREFIX_NAME));
        wr_name.key.insert(wr_name.key.end(), h160, h160 + 20);
        std::string label = "Address " + std::to_string(i + 1);
        wr_name.value.assign(label.begin(), label.end());
        out_records.push_back(std::move(wr_name));

        // ckey record (only when encrypted)
        if (have_master) {
            uint8_t priv[32];
            std::memcpy(priv, privkeys[i].data(), 32);
            std::vector<uint8_t> ct;
            std::string ckerr;
            if (!wallet::encrypt_private_key(master_key, priv, ct, ckerr)) {
                platform::secure_wipe(priv, 32);
                err = "ckey encryption failed: " + ckerr;
                return false;
            }
            platform::secure_wipe(priv, 32);
            bdb::WriteRecord wr_ckey;
            wr_ckey.key.assign(wallet::PREFIX_CKEY, wallet::PREFIX_CKEY + std::strlen(wallet::PREFIX_CKEY));
            wr_ckey.key.insert(wr_ckey.key.end(), h160, h160 + 20);
            // Value: CDataStream-compatible serialization of CryptedKey,
            //   which begins with a varint-length-prefixed vchCryptedSecret.
            parser::Serializer sc;
            sc.put_bytes_prefixed(ct);
            wr_ckey.value = sc.take();
            out_records.push_back(std::move(wr_ckey));
        }
    }

    // Add one pool record per key
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        bdb::WriteRecord wr;
        wr.key.assign(wallet::PREFIX_POOL, wallet::PREFIX_POOL + std::strlen(wallet::PREFIX_POOL));
        // pool key has an int64 pool index suffix
        int64_t idx = int64_t(i + 1);
        for (int b = 0; b < 8; ++b) wr.key.push_back(uint8_t((idx >> (b*8)) & 0xff));
        // Value: int64 nTime + varint-prefixed pubkey
        parser::Serializer sp;
        sp.put_i64(int64_t(1234567890LL + i));
        sp.put_bytes_prefixed(pubkeys[i]);
        wr.value = sp.take();
        out_records.push_back(std::move(wr));
    }

    // Wipe master key from memory
    master_key.clear();

    return true;
}

} // namespace

int cmd_create(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    CreateArgs a;
    std::string err;
    if (!parse_args(argc, argv, a, err)) {
        std::cerr << "Error: " << err << "\n"
                  << "Usage: btc-legacy create --year YYYY --out FILE "
                     "[--encrypted] [--passphrase X] [--keys N] "
                     "[--seed N] [--testnet] [--json]\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::vector<bdb::WriteRecord> records;
    std::vector<uint8_t> default_key;
    if (!build_records(a, records, default_key, err)) {
        std::cerr << "Error: " << err << "\n";
        return ExitCode::GENERAL_ERROR;
    }
    std::string werr;
    if (!bdb::write_bdb_hash_file(a.out_path, records, bdb::WALLET_DEFAULT_PAGESIZE, &werr)) {
        std::cerr << "Error: " << werr << "\n";
        return ExitCode::GENERAL_ERROR;
    }
    // Compute the default address for reporting
    uint8_t h160[20];
    std::string addr = "(none)";
    if (crypto::hash160(default_key, h160)) {
        uint8_t version = a.testnet ? 0x6f : 0x00;
        addr = crypto::hash160_to_p2pkh_address(h160, version);
    }
    if (g_json_mode) {
        util::JsonObject o;
        o["out"] = a.out_path;
        o["year"] = int64_t(a.year);
        o["encrypted"] = a.encrypted;
        o["keys"] = int64_t(a.keys);
        o["records"] = int64_t(records.size());
        o["default_address"] = addr;
        o["testnet"] = a.testnet;
        std::cout << util::JsonValue(o).to_string() << "\n";
    } else {
        std::cout << "Created synthetic test wallet\n\n"
                  << "Year             : " << a.year << "\n"
                  << "Out              : " << a.out_path << "\n"
                  << "Encrypted        : " << (a.encrypted ? "YES" : "NO") << "\n"
                  << "Key count        : " << a.keys << "\n"
                  << "Records          : " << records.size() << "\n"
                  << "Testnet          : " << (a.testnet ? "YES" : "NO") << "\n"
                  << "Default address  : " << addr << "\n\n"
                  << "NOTE: this is a synthetic test fixture and contains no historical funds.\n";
    }
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
