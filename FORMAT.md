# `wallet.dat` Format Reference

This document describes the on-disk format of legacy Bitcoin Core
wallet files (`wallet.dat`) as understood by `btc-legacy`. It is
derived from the historical Bitcoin Core source (`src/wallet/`,
`src/bdb/`) and the Berkeley DB 4.x page-layout documentation
(`dbinc/db_page.h`).

## File-level layout

A `wallet.dat` file is a **Berkeley DB 4.x hash database**. The file
is divided into fixed-size **pages**. Page size defaults to **4096
bytes** for Bitcoin Core wallets.

```
+------------+------------+------------+------------+----+------------+
| Page 0     | Page 1     | Page 2     | Page 3     | …  | Page N     |
| (metadata) | (data)     | (data)     | (data)     |    | (data)     |
+------------+------------+------------+------------+----+------------+
```

### Metadata page (page 0) — `HASHMETA`

Page 0 contains the database metadata. Relevant fields (all
little-endian):

| Offset | Size | Field          | Notes                                              |
|--------|------|----------------|----------------------------------------------------|
| 0      | 8    | `lsn`          | Log sequence number (unused for read-only access)  |
| 8      | 4    | `pgno`         | Always `0` for the metadata page                   |
| 12     | 4    | `magic`        | `0x00061561` for BDB hash                           |
| 16     | 4    | `version`      | `9` for BDB 4.x hash                               |
| 20     | 4    | `pagesize`     | Typically `4096`                                    |
| 24     | 1    | `encrypt_alg`  | `0` for unencrypted DB                              |
| 25     | 1    | `page_type`    | `8` = `P_HASHMETA`                                  |
| 26     | 1    | `metaflags`    |                                                    |
| 27..28 | 2    | (reserved)     |                                                    |
| 29..44 | 16   | `encrypt_iv`   | Only used if DB-level encryption is enabled         |
| 45     | 4    | `flags`        | DB_AM_HASH, DB_AM_DUP, etc.                         |
| 61     | 4    | `last_pgno`    | Highest page number in use                          |
| 69     | 4    | `keycount`     | (Hash)                                              |
| 73     | 4    | `record_count` | (Hash)                                              |
| 84+    | …    | hash-specific | `maxbucket`, `high_mask`, `low_mask`, `ffactor`, `nelem`, `h_charkey` |

### Data pages (pages 1..N)

Each data page begins with a **26-byte page header**:

| Offset | Size | Field        | Notes                                        |
|--------|------|--------------|----------------------------------------------|
| 0      | 8    | `lsn`        |                                              |
| 8      | 4    | `pgno`       |                                              |
| 12     | 4    | `prev_pgno`  | Linked-list pointer for overflow pages       |
| 16     | 4    | `next_pgno`  | Linked-list pointer for overflow pages       |
| 20     | 2    | `entries`    | Number of items on this page                 |
| 22     | 2    | `hf_offset`  | High free byte offset (where free space ends) |
| 24     | 1    | `level`      | Btree level (always `1` for hash leaves)     |
| 25     | 1    | `type`       | `13` = `P_HASH_UNSORTED`, `14` = `P_LHASH`  |

After the header, an **item offset table** of `entries * 2` bytes
holds `uint16_t` offsets into the page, pointing to **BKEYDATA** items.

#### BKEYDATA item layout

| Offset | Size | Field  | Notes                                              |
|--------|------|--------|----------------------------------------------------|
| 0      | 2    | `type` | `1` = `B_KEYDATA`, `3` = `B_OVERFLOW`              |
| 2      | 2    | `len`  | Length of the `data` field                          |
| 4      | `len`| `data` | The key or value bytes                              |

For `B_OVERFLOW` items, the item is 10 bytes total (`type:u16`,
`tlen:u32`, `pgno:u32`) and the actual data lives in a chain of
overflow pages linked by `next_pgno`.

For hash pages, items come in **(key, value)** pairs at even/odd
indices in the offset table.

## Wallet record prefixes

Each BDB key in a wallet is a **prefix string** (e.g. `"key"`,
`"ckey"`, `"mkey"`) optionally followed by binary suffix bytes (e.g.
a 20-byte hash160, or an `int64` pool index). The value is opaque
binary data whose interpretation depends on the prefix.

| Prefix       | Suffix               | Value (CDataStream-encoded)                                          |
|--------------|----------------------|----------------------------------------------------------------------|
| `version`    | (none)               | `uint32` wallet version LE                                            |
| `defaultkey` | (none)               | CPubKey (33 or 65 bytes)                                              |
| `key`        | 20-byte hash160      | CPubKey + int64 nTime + vchKeyMeta                                    |
| `keymeta`    | 20-byte hash160      | uint8 nVersion + int64 nTime + vchPubKey + optional hdKeypath       |
| `ckey`       | 20-byte hash160      | varint(vchCryptedSecret) + optional vchPubKey                        |
| `mkey`       | uint32 id (LE)       | varint(vchCryptedKey) + varint(vchSalt) + nDerivationMethod + nDeriveCount |
| `name`       | 20-byte hash160 (or other) | UTF-8 label string                                              |
| `pool`       | int64 index          | int64 nTime + vchPubKey                                              |
| `tx`         | uint256 txid         | CWalletTx serialization                                                |
| `bestblock`  | (none)               | CBlockLocator                                                         |
| `setting`    | string               | setting value                                                         |
| `destdata`   | hash160 + str key    | string value                                                          |
| `watchs`     | 20-byte hash160      | (presence implies watch-only)                                        |
| `hdchain`    | (none)               | CHDChain serialization                                                 |
| `flags`      | (none)               | uint64 flags                                                          |

## Wallet encryption (CCrypter)

Bitcoin Core 0.4.0+ wallet encryption is **not** a custom algorithm.
It uses OpenSSL primitives in a fixed scheme:

1. A random 32-byte **master key** is generated.
2. A random 8-byte **salt** is generated.
3. A 32-byte AES key + 16-byte AES IV is derived from the passphrase
   and the salt using OpenSSL's
   `EVP_BytesToKey(EVP_sha512(), NULL, salt, passphrase, count=25000, ...)`.
4. The 32-byte master key is AES-256-CBC encrypted with the derived
   key/IV (PKCS7 padding → 48-byte ciphertext).
5. The result is stored in an `mkey` record alongside the salt,
   `nDerivationMethod=0`, and `nDeriveCount=25000`.
6. For each private key, a fresh random 16-byte IV is generated and
   prepended to the ciphertext. The 32-byte private key is
   AES-256-CBC encrypted with the **master** key (not the passphrase
   key) and stored in a `ckey` record.

Passphrase verification therefore reduces to:

* Read the `mkey` record.
* Derive (key, IV) from passphrase + salt + count.
* Decrypt `vchCryptedKey`. If PKCS7 padding is valid **and** the
  resulting plaintext is exactly 32 bytes long, the passphrase is
  almost certainly correct.
* Cross-check: decrypt one `ckey` record with the derived master key.
  If the result is exactly 32 bytes, confidence is very high.

A wrong passphrase yields a padding error with probability ≈ `255/256`,
so false positives are astronomically rare.
