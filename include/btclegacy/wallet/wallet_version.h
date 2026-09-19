// btclegacy/wallet/wallet_version.h
#pragma once
#include <cstdint>
#include <string>
namespace btclegacy::wallet {

// Map a wallet_version uint32 to a human-friendly description (best-effort).
// Returns "Unknown" if we have no historical evidence — never guesses.
struct VersionInfo {
    std::string pretty;     // "Bitcoin Core 0.4.0+" etc.
    std::string raw_hex;    // hex of uint32
    bool        known = false;
};

VersionInfo describe_version(uint32_t v);

} // namespace btclegacy::wallet
