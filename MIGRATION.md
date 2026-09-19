# Migration Guide

`btc-legacy migrate` produces a portable JSON descriptor of a legacy
wallet at a user-supplied `--out` path. The descriptor contains
addresses, public keys, and (if the wallet was encrypted and a
passphrase was supplied) WIF-encoded private keys.

## Migration workflow

The workflow follows the spec:

1. **Detect** — verify the file is a Berkeley DB hash wallet.
2. **Validate** — sanity-check BDB page structure and wallet records.
3. **Backup** — copy the source to `wallet.dat.backup-YYYYMMDD-HHMMSS`.
4. **Read** — iterate wallet records via `bdb::Reader`.
5. **Request passphrase** (if encrypted) — interactive prompt or one
   of the other passphrase sources.
6. **Decrypt required records** — verify the passphrase against the
   `mkey` record, then decrypt each `ckey` with the master key.
7. **Extract supported material** — addresses (P2PKH), public keys,
   WIF private keys, transaction counts, labels.
8. **Verify extracted material** — ensure each decrypted private key
   re-derives to the matching public key.
9. **Create destination** — write the JSON descriptor to `--out`.
10. **Verify destination** — re-open and parse it.
11. **Generate migration report** — print or emit JSON.

The source file is **never modified**.

## Partial migration

If any record could not be parsed or decrypted, the migration is
reported as `PARTIAL MIGRATION` and exit code 8 is returned. The
destination file is still written (with whatever could be extracted).

## Destination format

The destination file is a JSON document with the following shape
(subject to evolution; check `format_version`):

```json
{
  "format": "btc-legacy-migration",
  "format_version": 1,
  "source_path": "wallet.dat",
  "source_wallet_version": 60000,
  "compatibility": "Legacy Bitcoin Core (encrypted-capable)",
  "encrypted_source": true,
  "migrated_at": "2026-09-19T04:51:13Z",
  "addresses": ["1...", "1...", ...],
  "public_keys": ["02ab...", "02cd...", ...],
  "private_keys": [
    { "wif": "L...", "compressed": true },
    ...
  ],
  "tx_count": 17,
  "pool_count": 100,
  "name_count": 5,
  "full_migration": true
}
```

## What is NOT migrated

* Wallet transaction records (`tx`) — counted but not decoded.
* HD chain metadata (`hdchain`).
* Watch-only addresses (`watchs`).
* Wallet settings (`setting`).
* Block locator (`bestblock`).

The destination file is therefore a **key-and-address export**, not a
full wallet. To actually use the migrated material, import the
addresses / public keys / private keys into a modern wallet (Bitcoin
Core's `importmulti`/`descriptors` API, Electrum, Sparrow, etc.).

## Security warnings

* The destination file contains **plaintext private keys** if the
  source wallet was encrypted. Handle it with the same care as the
  original wallet.dat.
* After migration, the destination file should be moved to
  encrypted storage and the source wallet deleted only after
  verifying that all keys have been successfully imported elsewhere.
