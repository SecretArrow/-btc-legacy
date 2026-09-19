// btclegacy/wallet/wallet_parser.h
#pragma once
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/bdb/bdb_reader.h"
#include <string>
#include <memory>

namespace btclegacy::wallet {

// Parse a wallet file into a ParsedWallet view. Internally opens the
// BDB reader and iterates records. The wallet is loaded into memory
// in ParsedWallet (because individual record sizes are tiny and the
// total record count is small for a personal wallet — typically
// thousands, not millions).
//
// On the file structure side we read pages on demand so large
// wallet.dat files do not need to be loaded whole.
//
struct ParseStats {
    uint32_t records_seen = 0;
    uint32_t records_parsed = 0;
    uint32_t unknown_records = 0;
    uint32_t errors = 0;
};

bool parse_wallet(const std::string& path,
                  ParsedWallet& out,
                  std::string& err,
                  ParseStats* stats = nullptr,
                  bool* is_bdb = nullptr);

// Determine the compatibility category (EARLY/LEGACY/UNKNOWN/UNSUPPORTED)
ParsedWallet::Compatibility classify(const ParsedWallet& w);

const char* compatibility_string(ParsedWallet::Compatibility c);

} // namespace btclegacy::wallet
