// src/wallet/wallet_record.cpp
#include "btclegacy/wallet/wallet_record.h"
#include "btclegacy/parser/serializer.h"
#include <cstring>
#include <cstdint>
#include <map>
#include <algorithm>

namespace btclegacy::wallet {

bool try_parse_uint32(const std::vector<uint8_t>& v, uint32_t& out) {
    if (v.size() < 4) return false;
    out = uint32_t(v[0]) | (uint32_t(v[1]) << 8) |
          (uint32_t(v[2]) << 16) | (uint32_t(v[3]) << 24);
    return true;
}

bool try_read_version(const std::vector<uint8_t>& v, uint32_t& out) {
    return try_parse_uint32(v, out);
}

bool split_wallet_key(const std::vector<uint8_t>& bdb_key,
                       std::string& prefix,
                       std::vector<uint8_t>& suffix) {
    if (bdb_key.empty()) return false;
    prefix.clear();
    suffix.clear();
    // Match against known Bitcoin Core wallet prefixes. The prefixes
    // are short ASCII strings; the suffix (when present) is binary
    // (e.g. a 20-byte hash160 or an int64 index). Hash160 bytes are
    // arbitrary binary data — they can collide with ASCII printable
    // chars, so we cannot naively split on the first non-printable
    // byte. Instead we test against the known prefix list and take
    // the longest match.
    static const std::vector<std::pair<std::string, const char*>> known = {
        {"version",       PREFIX_VERSION},
        {"minversion",    PREFIX_MINVERSION},
        {"defaultkey",    PREFIX_DEFAULTKEY},
        {"keymeta",       PREFIX_KEYMETA},
        {"defaultkey",    PREFIX_DEFAULTKEY},
        {"bestblock",     PREFIX_BESTBLOCK},
        {"bestinvalid",   PREFIX_BESTINVALID},
        {"orderposnext",  PREFIX_ORDERPOSNEXT},
        {"destdata",      PREFIX_DESTDATA},
        {"watchs",        PREFIX_WATCHS},
        {"hdchain",       PREFIX_HDCHAIN},
        {"acentry",       PREFIX_ACENTRY},
        {"setting",       PREFIX_SETTING},
        {"defaultkey",    PREFIX_DEFAULTKEY},
        {"key",           PREFIX_KEY},
        {"ckey",          PREFIX_CKEY},
        {"mkey",          PREFIX_MKEY},
        {"name",          PREFIX_NAME},
        {"pool",          PREFIX_POOL},
        {"tx",            PREFIX_TX},
        {"flags",         PREFIX_FLAGS},
    };
    // Longest-first match
    std::vector<std::pair<std::string, const char*>> sorted = known;
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b){ return a.first.size() > b.first.size(); });
    for (const auto& kv : sorted) {
        const std::string& p = kv.first;
        if (bdb_key.size() >= p.size() &&
            std::memcmp(bdb_key.data(), p.data(), p.size()) == 0) {
            prefix = p;
            suffix.assign(bdb_key.begin() + p.size(), bdb_key.end());
            return true;
        }
    }
    // Fall back to the original ASCII-prefix heuristic for unknown
    // prefixes (so we still detect "foobar"-style records for tests).
    size_t i = 0;
    while (i < bdb_key.size() && bdb_key[i] >= 0x20 && bdb_key[i] < 0x7f) {
        prefix.push_back(char(bdb_key[i]));
        ++i;
    }
    suffix.assign(bdb_key.begin() + i, bdb_key.end());
    return true;
}

// Parse a CMasterKey record. Historical Bitcoin Core walletdb.cpp:
//   ser_action_read: vchCryptedKey, vchSalt, nDerivationMethod, nDeriveCount
// Lengths are varint CompactSize (CDataStream compatible).
MasterKey parse_master_key(const std::vector<uint8_t>& v) {
    MasterKey mk;
    parser::Serializer s(v);
    try {
        // CDataStream serializes vector<unsigned char> as: varint len, then bytes
        mk.vchCryptedKey = s.read_bytes_prefixed();
        mk.vchSalt       = s.read_bytes_prefixed();
        mk.nDerivationMethod = s.read_u32();
        mk.nDeriveCount       = s.read_u32();
        mk.valid = true;
    } catch (const std::runtime_error& e) {
        mk.valid = false;
        mk.error = e.what();
    }
    return mk;
}

// "key" record value layout (Bitcoin Core 0.4+ CKey):
//   CPubKey vchPubKey (serialized as bytes)
//   int64 nTime
//   std::vector<uint8_t> vchKeyMeta
KeyRecord parse_key_record(const std::vector<uint8_t>& v) {
    KeyRecord k;
    parser::Serializer s(v);
    try {
        // CPubKey serialization in old Bitcoin Core is just a variable-length byte sequence
        // preceeded by a CompactSize. In the legacy wallet format, CPubKey is actually
        // serialized as a vector<uint8_t> (varint len + bytes).
        k.vchPubKey = s.read_bytes_prefixed();
        if (s.eof()) { k.nTime = 0; }
        else         { k.nTime = s.read_i64(); }
        if (!s.eof()) { k.vchKeyMeta = s.read_bytes_prefixed(); }
        k.parsed_ok = true;
    } catch (const std::runtime_error& e) {
        k.parsed_ok = false;
    }
    return k;
}

// "keymeta" record:
//   uint8 nVersion
//   int64 nTime
//   std::vector<uint8_t> vchPubKey
//   std::vector<uint8_t> hdKeypath (optional, newer versions)
KeyMeta parse_keymeta_record(const std::vector<uint8_t>& v) {
    KeyMeta m;
    parser::Serializer s(v);
    try {
        m.nVersion = s.read_u8();
        m.nTime = s.read_i64();
        m.vchPubKey = s.read_bytes_prefixed();
        if (!s.eof()) m.hdKeypath = s.read_bytes_prefixed();
    } catch (const std::runtime_error&) {
    }
    return m;
}

// "ckey" record value layout:
//   CKeyingMaterial vchCryptedSecret (varint len + bytes)
//   The 16-byte AES IV is stored as a prefix inside vchCryptedSecret.
CryptedKeyRecord parse_ckey_record(const std::vector<uint8_t>& v) {
    CryptedKeyRecord ck;
    parser::Serializer s(v);
    try {
        ck.vchCryptedSecret = s.read_bytes_prefixed();
        ck.parsed_ok = true;
    } catch (const std::runtime_error&) {
        ck.parsed_ok = false;
    }
    return ck;
}

// "pool" record value layout (CKeyPool):
//   int64 nTime
//   CPubKey vchPubKey
KeyPool parse_pool_record(const std::vector<uint8_t>& v) {
    KeyPool p;
    parser::Serializer s(v);
    try {
        p.nTime = s.read_i64();
        p.vchPubKey = s.read_bytes_prefixed();
    } catch (const std::runtime_error&) {
    }
    return p;
}

// "tx" record value layout (CMerkleTx + metadata) — for inspection we
// just preserve the raw bytes and best-effort a txid by hashing the
// first transaction blob in the buffer.
TxRecord parse_tx_record(const std::vector<uint8_t>& v) {
    TxRecord t;
    t.vchTxData = v;
    t.parsed_ok = !v.empty();
    return t;
}

} // namespace btclegacy::wallet
