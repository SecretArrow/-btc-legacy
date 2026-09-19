// src/cli/cmd_hashdump.cpp
//
// Export a legacy Bitcoin wallet's encryption material into hashcat's
// mode 11300 (Bitcoin Core wallet.dat) hash format.
//
// Once you have the hash dump, you can run hashcat against any GPU
// (Intel/AMD/NVIDIA via OpenCL) for massively-parallel KDF attack:
//
//   $ btc-legacy hashdump wallet.dat > hash.txt
//   $ hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'        # 4-digit PIN mask
//   $ hashcat -m 11300 hash.txt rockyou.txt           # dictionary
//
// Hash format (mode 11300, bitcoin2john compatible):
//
//   $bitcoin$<mlen>$<master_ct_hex>$8$<salt_hex>$<method>$<count>$2$00$<clen>$<ckey_ct_hex>$1
//
// Where:
//   <mlen>      = number of hex chars in <master_ct_hex>
//                 (e.g. 96 for a 48-byte encrypted master key, since
//                  48 bytes = 96 hex chars after PKCS7 padding of the
//                  32-byte master key)
//   <master_ct_hex> = hex of mkey.vchCryptedKey
//   <salt_hex>  = hex of mkey.vchSalt (always 16 hex chars / 8 bytes)
//   <method>    = mkey.nDerivationMethod (always 0 historically)
//   <count>     = mkey.nDeriveCount (e.g. 25000)
//   <clen>      = number of hex chars in <ckey_ct_hex>
//   <ckey_ct_hex> = hex of ckey.vchCryptedSecret = IV(16) + ct(48) = 64 bytes
//   2$00$       = literal separator (length-prefixed empty field used by
//                 bitcoin2john for an unspecified metadata slot)
//   $1          = literal tail marker
//
#include "btclegacy/cli/cmd_hashdump.h"
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_record.h"
#include <iostream>
#include <cstring>
#include <string>

namespace btclegacy::cli {
extern bool g_json_mode;
extern bool g_verbose_mode;
extern bool g_quiet_mode;
void apply_global_flags_for_subcommand(int argc, char** argv);

int cmd_hashdump(int argc, char** argv) {
    apply_global_flags_for_subcommand(argc, argv);
    if (argc < 3) {
        std::cerr <<
            "Usage: btc-legacy hashdump <wallet.dat> [--json]\n"
            "\n"
            "Export the wallet's mkey + first ckey record into hashcat mode 11300\n"
            "format, ready to be fed to hashcat:\n"
            "\n"
            "  $ btc-legacy hashdump wallet.dat > hash.txt\n"
            "  $ hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'\n"
            "\n"
            "Requires the wallet to be encrypted (have mkey + ckey records).\n";
        return ExitCode::INVALID_ARGUMENT;
    }
    std::string path = argv[2];
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
    if (!w.encrypted || w.master_keys.empty()) {
        std::cerr << "Error: wallet is not encrypted (no mkey record) — "
                     "nothing to hashdump.\n";
        return ExitCode::UNSUPPORTED_WALLET;
    }
    if (w.ckeys.empty()) {
        std::cerr << "Error: wallet has mkey but no ckey records — "
                     "cannot produce a verifiable hash (no ckey to "
                     "cross-check during KDF).\n";
        return ExitCode::UNSUPPORTED_WALLET;
    }

    // Pick the first valid mkey + first ckey
    const wallet::MasterKey& mk = w.master_keys[0];
    const wallet::CryptedKeyRecord& ck = w.ckeys[0];

    std::string master_ct_hex = util::to_hex(mk.vchCryptedKey);
    std::string salt_hex      = util::to_hex(mk.vchSalt);
    std::string ckey_ct_hex   = util::to_hex(ck.vchCryptedSecret);

    // bitcoin2john format
    std::string hash_str = "$bitcoin$" +
        std::to_string(master_ct_hex.size()) + "$" + master_ct_hex +
        "$8$" + salt_hex +
        "$" + std::to_string(mk.nDerivationMethod) +
        "$" + std::to_string(mk.nDeriveCount) +
        "$2$00$" +
        std::to_string(ckey_ct_hex.size()) + "$" + ckey_ct_hex +
        "$1";

    if (g_json_mode) {
        std::cout << "{\"hashcat_mode\":11300,"
                  << "\"hash\":\"" << hash_str << "\","
                  << "\"wallet\":\"" << path << "\","
                  << "\"mkey_count\":" << w.mkey_count << ","
                  << "\"ckey_count\":" << w.ckey_count << ","
                  << "\"derive_count\":" << mk.nDeriveCount << ","
                  << "\"method\":" << mk.nDerivationMethod
                  << "}\n";
    } else {
        std::cout << hash_str << "\n";
        if (g_verbose_mode) {
            std::cerr << "# wallet: " << path << "\n"
                      << "# mkey records: " << w.mkey_count << "\n"
                      << "# ckey records: " << w.ckey_count << "\n"
                      << "# derive_method: " << mk.nDerivationMethod << "\n"
                      << "# derive_count:  " << mk.nDeriveCount << "\n"
                      << "# salt (hex):    " << salt_hex << "\n"
                      << "# master_ct (hex, " << (master_ct_hex.size()/2)
                      << " bytes): " << master_ct_hex << "\n"
                      << "# ckey (hex, " << (ckey_ct_hex.size()/2)
                      << " bytes): " << ckey_ct_hex << "\n"
                      << "#\n"
                      << "# Run hashcat:\n"
                      << "#   hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'\n"
                      << "#   hashcat -m 11300 hash.txt wordlist.txt\n";
        }
    }
    return ExitCode::SUCCESS;
}

} // namespace btclegacy::cli
