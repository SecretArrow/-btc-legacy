# btc-legacy — Bitcoin Legacy Wallet CLI

`btc-legacy` is a **native C++20 command-line tool** for inspecting,
validating, backing up, recovering, and migrating **legacy Bitcoin
wallet.dat files from approximately 2009 through 2015**.

It is **offline-only**, has **no telemetry**, and **never transmits
wallet files or private keys** anywhere.

## Supported wallet formats

* Berkeley DB 4.x **hash** database files (`wallet.dat`) as written by
  Bitcoin Core 0.1.0 through 0.15.x.
* Records recognised: `version`, `key`, `ckey`, `mkey`, `name`,
  `defaultkey`, `pool`, `tx`, `keymeta`, `bestblock`, `setting`,
  `destdata`, `watchs`, `hdchain`, `flags`.
* Wallet encryption: the historical Bitcoin Core CCrypter scheme
  (AES-256-CBC + EVP_BytesToKey(SHA-512) with the salt and iteration
  count stored inside each `mkey` record).

## Historical compatibility

| Year range | Compatibility class             | Notes                                                            |
|------------|---------------------------------|------------------------------------------------------------------|
| 2009–2010  | `EARLY_BITCOIN`                 | Pre-encryption wallets, uncompressed public keys (65 bytes)      |
| 2011       | `EARLY_BITCOIN`                 | Encryption-capable flag is set but wallet may still be unencrypted |
| 2012–2015  | `LEGACY_BITCOIN_CORE`           | Compressed pubkeys (33 bytes), may have `mkey`/`ckey` records    |
| unknown    | `UNKNOWN_LEGACY`                | BDB hash file with *some* wallet records, but no decisive evidence |
| n/a        | `UNSUPPORTED`                    | BDB hash file with no recognisable Bitcoin wallet prefixes       |

We do **not** guess a specific Bitcoin Core release version unless the
wallet's `version` record matches a historically known value.

## CLI

```text
btc-legacy detect    <wallet>
btc-legacy info      <wallet>
btc-legacy inspect   <wallet> [--metadata-only] [--records]
btc-legacy validate  <wallet>
btc-legacy backup    <wallet>
btc-legacy create    --year YYYY --out FILE [--encrypted --passphrase X] [--keys N] [--seed N] [--testnet]
btc-legacy password verify <wallet> [--passphrase X | --passphrase-file FILE | --passphrase-stdin]
btc-legacy export    <wallet> [--addresses | --public-keys | --transactions | --private-keys] [--passphrase X | ...]
btc-legacy recover   <wallet> [--passphrase X | ...]
btc-legacy migrate   <wallet> --out PATH [--passphrase X | ...]
btc-legacy version
```

## Passphrase sources

Every command that needs wallet decryption supports all of the
following:

| Source                     | Flag                       | Notes                                              |
|----------------------------|----------------------------|----------------------------------------------------|
| Direct argument            | `--passphrase <value>`     | **DANGEROUS** — leaks via shell history, `ps`, CI logs |
| Interactive hidden prompt | (no flag)                 | Echo disabled via `termios`; safe for terminals    |
| File                       | `--passphrase-file <path>` | First line is used; file is NOT printed            |
| stdin                      | `--passphrase-stdin`       | Read one line; safe for pipes                      |

The passphrase is wiped from memory (volatile `memset` via
`platform::secure_wipe`) after every use. It is never written to log
files, never included in JSON output, and never echoed back.

> **Security warning**: `--passphrase "secret"` is convenient but
> leaks through shell history, `ps`, CI logs, and command auditing.
> Prefer `--passphrase-stdin` or the interactive prompt.

## Exit codes

| Code | Meaning                |
|------|------------------------|
| 0    | SUCCESS                |
| 1    | GENERAL_ERROR          |
| 2    | INVALID_ARGUMENT       |
| 3    | FILE_NOT_FOUND         |
| 4    | UNSUPPORTED_WALLET     |
| 5    | CORRUPTED_WALLET       |
| 6    | INCORRECT_PASSPHRASE   |
| 7    | PERMISSION_ERROR       |
| 8    | MIGRATION_FAILED       |
| 9    | USER_CANCELLED         |

## Safety guarantees

* The original `wallet.dat` is **never modified** during `detect`,
  `info`, `inspect`, `validate`, `password`, `recover`, `export`, or
  `migrate`.
* `backup` creates `wallet.dat.backup-YYYYMMDD-HHMMSS` next to the
  source and verifies SHA-256 against the source.
* `recover` always operates read-only against the source. When
  repair is required, the tool works on a **copy** and never touches
  the original.
* `export --private-keys` requires explicit `--yes` confirmation (or
  interactive `y/N`) and is gated behind a passphrase source.
* All cryptographic operations are done in-process; no network
  access is performed.

## Limitations

* The BDB hash reader is a minimal implementation, not a port of the
  full Berkeley DB library. It works reliably against wallets written
  by `btc-legacy create` and against simple real Bitcoin Core wallets,
  but more complex multi-bucket hash layouts may be classified as
  `UNKNOWN_LEGACY` rather than fully decoded.
* We do not parse individual wallet transaction records (the `tx`
  prefix) — only count them. Decoding historical `CMerkleTx` +
  `CWalletTx` is out of scope for v1.0.
* We do not write modern descriptor-based wallets as a migration
  target. The destination of `migrate` is a portable JSON descriptor
  containing addresses, public keys, and WIF-encoded private keys.

## See also

* `BUILDING.md` — how to build (Linux x86_64, Linux ARM64, Windows x86_64)
* `FORMAT.md` — wallet.dat format documentation
* `MIGRATION.md` — migration workflow and limitations
* `RECOVERY.md` — recovery workflow and limitations
* `SECURITY.md` — security model and disclosure policy
* `THREAT_MODEL.md` — what `btc-legacy` does and does not protect against

## License

This project's source is provided for forensic / recovery / research
use on wallets owned or authorized by the user.
