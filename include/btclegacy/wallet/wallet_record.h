// btclegacy/wallet/wallet_record.h
#pragma once
//
// Legacy Bitcoin wallet record types & serialization helpers.
//
// Historical reference: Bitcoin Core src/wallet/walletdb.cpp and
// src/wallet/wallet.h from approximately 2009 through 2015.
//
// Records in wallet.dat are keyed by a small string prefix that names
// the logical object. Some prefixes carry an additional key suffix
// (e.g. a CKeyID hash160 for "key", "ckey", "name"). The most common
// prefixes are:
//
//   "version"         -> wallet version (single 4-byte uint32 LE value)
//   "defaultkey"      -> default CKey
//   "key"             -> public key + key metadata (CKe) per <pubkey-hash>
//   "keymeta"         -> key metadata (CPubKey version + creation time)
//   "ckey"            -> encrypted private key (CCrypter output)
//   "mkey"            -> master encryption key record (CMasterKey)
//   "name"            -> label/name for an address
//   "pool"            -> keypool entries (reserved generated keys)
//   "tx"              -> wallet transaction records
//   "bestblock"       -> last synced block locator
//   "setting"         -> key/value setting
//   "bestchain"       -> reorg log
//   "orderposnext"
//   "defaultkey"
//   "destdata"
//   "watchs"
//   "hd" / "hdchain"  -> BIP32 chain metadata (newer)
//   "flags"
//
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <optional>

namespace btclegacy::wallet {

// Known wallet record prefixes (historical Bitcoin Core walletdb.cpp)
constexpr const char* PREFIX_VERSION      = "version";
constexpr const char* PREFIX_NAME         = "name";
constexpr const char* PREFIX_DEFAULTKEY   = "defaultkey";
constexpr const char* PREFIX_KEY         = "key";
constexpr const char* PREFIX_KEYMETA     = "keymeta";
constexpr const char* PREFIX_CKEY        = "ckey";
constexpr const char* PREFIX_MKEY        = "mkey";
constexpr const char* PREFIX_POOL         = "pool";
constexpr const char* PREFIX_TX          = "tx";
constexpr const char* PREFIX_BESTBLOCK   = "bestblock";
constexpr const char* PREFIX_ORDERPOSNEXT= "orderposnext";
constexpr const char* PREFIX_SETTING     = "setting";
constexpr const char* PREFIX_DESTDATA    = "destdata";
constexpr const char* PREFIX_WATCHS      = "watchs";
constexpr const char* PREFIX_HDCHAIN     = "hdchain";
constexpr const char* PREFIX_FLAGS       = "flags";
constexpr const char* PREFIX_ACENTRY     = "acentry";
constexpr const char* PREFIX_BESTINVALID= "bestinvalid";
constexpr const char* PREFIX_MINVERSION  = "minversion";

// Wallet version constants (historical Bitcoin Core wallet.h)
constexpr uint32_t WALLET_VERSION_BASE            = 60000; // 0.6.0
constexpr uint32_t WALLET_VERSION_DETERMINISTIC   = 60000; // early deterministic
constexpr uint32_t WALLET_VERSION_KEYMETA         = 60000;
constexpr uint32_t WALLET_VERSION_WITH_MKEY       = 60000; // crypto added in 0.4.0
constexpr uint32_t WALLET_VERSION_HD              = 130000; // BIP32 added in 0.13

// Master-key record (CMasterKey), as serialized historically.
struct MasterKey {
    std::vector<uint8_t> vchCryptedKey;       // AES-256-CBC(master, derived) of master key
    std::vector<uint8_t> vchSalt;             // 8 bytes
    uint32_t nDerivationMethod = 0;           // historically 0 == EVP_BytesToKey(SHA512)
    uint32_t nDeriveCount = 0;                 // iterations (e.g. 25000 historically)
    bool valid = false;
    std::string error;
};

// Key-pool entry (CKeyPool)
struct KeyPool {
    int64_t nTime = 0;
    std::vector<uint8_t> vchPubKey; // 33 or 65 bytes
};

// Public key entry under "key" prefix (CKe). Historically the value
// contained (CPubKey + nTime + vchPubKeyMeta + derivation path ...) but
// for parsing we keep it as raw bytes plus a parsed metadata view.
struct KeyRecord {
    std::vector<uint8_t> vchPubKey;     // 33 (compressed) or 65 (uncompressed)
    int64_t nTime = 0;
    std::vector<uint8_t> vchKeyMeta;    // raw, opaque
    bool parsed_ok = false;
};

// "keymeta" record (v1: int64 nTime + vchPubKey)
struct KeyMeta {
    int64_t nTime = 0;
    std::vector<uint8_t> vchPubKey;
    std::vector<uint8_t> hdKeypath;    // optional, newer
    uint8_t nVersion = 0;
};

// Encrypted private key record under "ckey" prefix.
// Value layout: <CPubKey bytes> is NOT stored — the key prefix carries
// the hash of the pubkey. The value is just: <encrypted privkey bytes>
// encrypted with AES-256-CBC using the master key.
struct CryptedKeyRecord {
    std::vector<uint8_t> vchCryptedSecret;
    std::vector<uint8_t> vchPubKey;   // captured from sibling "key" record
    bool parsed_ok = false;
};

// Wallet transaction record (placeholder, opaque bytes + txid)
struct TxRecord {
    std::vector<uint8_t> vchTxData;
    std::string txid;
    bool parsed_ok = false;
};

// Logical view of a wallet parsed from BDB records.
struct ParsedWallet {
    // Raw record counts by prefix
    std::map<std::string, uint32_t> record_counts;

    // Key state
    bool encrypted = false;
    bool has_master_key = false;
    uint32_t wallet_version = 0;
    uint32_t key_count = 0;
    uint32_t ckey_count = 0;
    uint32_t mkey_count = 0;
    uint32_t name_count = 0;
    uint32_t pool_count = 0;
    uint32_t tx_count = 0;
    uint32_t defaultkey_present = false;
    uint32_t watchonly_count = 0;
    uint32_t hd_chain_present = false;

    // Decoded structures (best-effort)
    std::vector<MasterKey> master_keys;
    std::vector<KeyRecord> keys;
    std::vector<CryptedKeyRecord> ckeys;
    std::vector<KeyPool> pool;
    std::vector<std::pair<std::string, std::string>> names; // (label-key, label)
    std::vector<TxRecord> txs;
    std::vector<std::pair<std::string, std::vector<uint8_t>>> unknown_records; // (prefix, raw value)

    // Compatibility classification
    enum class Compatibility {
        EARLY_BITCOIN,         // pre-0.4 unencrypted wallet, basic key/tx records
        LEGACY_BITCOIN_CORE,   // 0.4+ encrypted-capable wallet with mkey/ckey
        UNKNOWN_LEGACY,        // bdb hash file with some wallet records but uncertain
        UNSUPPORTED,           // bdb hash file with no wallet records
    } compat = Compatibility::UNSUPPORTED;

    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

// Parsing helpers
bool try_parse_uint32(const std::vector<uint8_t>& v, uint32_t& out);

MasterKey parse_master_key(const std::vector<uint8_t>& v);
KeyRecord parse_key_record(const std::vector<uint8_t>& v);
KeyMeta parse_keymeta_record(const std::vector<uint8_t>& v);
CryptedKeyRecord parse_ckey_record(const std::vector<uint8_t>& v);
KeyPool parse_pool_record(const std::vector<uint8_t>& v);
TxRecord parse_tx_record(const std::vector<uint8_t>& v);

// Read the "version" record's value (raw bytes) into a uint32. Returns
// false if the value is missing or malformed.
bool try_read_version(const std::vector<uint8_t>& v, uint32_t& out);

// Strip the prefix from a BDB key, returning the prefix name and any
// remaining bytes (e.g. a hash160 suffix). Returns false for empty keys.
bool split_wallet_key(const std::vector<uint8_t>& bdb_key,
                      std::string& prefix,
                      std::vector<uint8_t>& suffix);

} // namespace btclegacy::wallet
