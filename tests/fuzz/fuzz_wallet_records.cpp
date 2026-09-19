// tests/fuzz/fuzz_wallet_records.cpp
//
// Fuzz wallet record deserialization. Build random byte streams and
// pass them through each record-type parser. Each parser must
// gracefully return a record with parsed_ok=false rather than crash.
//
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/wallet/wallet_parser.h"
#include <vector>
#include <string>
#include <cstring>

int fuzz_wallet_records(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0;
    // Pass the same arbitrary bytes through every record parser
    auto mk = btclegacy::wallet::parse_master_key(data);
    auto k  = btclegacy::wallet::parse_key_record(data);
    auto km = btclegacy::wallet::parse_keymeta_record(data);
    auto ck = btclegacy::wallet::parse_ckey_record(data);
    auto pl = btclegacy::wallet::parse_pool_record(data);
    auto tx = btclegacy::wallet::parse_tx_record(data);
    (void)mk; (void)k; (void)km; (void)ck; (void)pl; (void)tx;
    return 0;
}
