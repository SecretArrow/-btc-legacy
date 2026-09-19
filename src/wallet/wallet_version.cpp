// src/wallet/wallet_version.cpp
//
// Map a wallet "version" uint32 to a human-friendly description.
// We are deliberately conservative: only known historical Bitcoin Core
// wallet versions are mapped to a pretty string; anything else is
// reported as Unknown rather than invented.
//
#include "btclegacy/wallet/wallet_version.h"
#include "btclegacy/util/strings.h"
#include <cstdint>
#include <map>

namespace btclegacy::wallet {

VersionInfo describe_version(uint32_t v) {
    VersionInfo vi;
    vi.raw_hex = util::to_hex(reinterpret_cast<const uint8_t*>(&v), 4);
    // Historical Bitcoin Core wallet.h enum WalletFeature:
    //   FEATURE_BASE = 10500  (0.5.0 baseline)
    //   FEATURE_WALLETCRYPT = 40000  (0.4.0)
    //   FEATURE_COMPRPUBKEY = 60000  (0.6.0 compressed pubkeys)
    //   FEATURE_HD            = 130000 (0.13.0)
    //   FEATURE_HD_SPLIT      = 139900 (0.14.x split hd)
    //   FEATURE_NO_DEFAULT_KEY= 159900 (0.15.x default-key removal)
    //   FEATURE_WITNESS        = 160300 (0.16.x segwit)
    //   ...
    // Older wallets used uint32 values around 60000 (0.6.0 default).
    if (v == 0) {
        vi.pretty = "Pre-0.4 Bitcoin (no version record)";
        vi.known = true;
    } else if (v == 60000) {
        vi.pretty = "Bitcoin Core 0.6.0 (compressed pubkeys, pre-HD)";
        vi.known = true;
    } else if (v == 10500) {
        vi.pretty = "Bitcoin Core 0.5.0 wallet";
        vi.known = true;
    } else if (v == 40000) {
        vi.pretty = "Bitcoin Core 0.4.0 wallet (encryption-capable)";
        vi.known = true;
    } else if (v == 130000) {
        vi.pretty = "Bitcoin Core 0.13.0+ (BIP32 HD wallet)";
        vi.known = true;
    } else if (v == 139900) {
        vi.pretty = "Bitcoin Core 0.14.x (HD split wallet)";
        vi.known = true;
    } else if (v == 159900) {
        vi.pretty = "Bitcoin Core 0.15.x (no default key)";
        vi.known = true;
    } else if (v == 160300) {
        vi.pretty = "Bitcoin Core 0.16.0+ (segwit wallet)";
        vi.known = true;
    } else {
        vi.pretty = "Unknown wallet version";
        vi.known = false;
    }
    return vi;
}

} // namespace btclegacy::wallet
