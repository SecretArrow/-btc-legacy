# Recovery Guide

`btc-legacy recover` performs **best-effort recovery** of readable
records from a damaged wallet.dat file.

## Workflow

```
wallet.dat
    ↓
1. Validate BDB structure
    ↓
2. Walk every page; classify as metadata / data / overflow / free
    ↓
3. For each data page, extract (key, value) records
    ↓
4. Records that fail to parse are counted as corrupted
    ↓
5. If encrypted and a passphrase is supplied, attempt passphrase
   verification against each mkey record
    ↓
6. If passphrase is correct, decrypt each ckey and report counts
    ↓
7. Output recovery report with one of: OK / PARTIALLY_RECOVERABLE / UNRECOVERABLE
```

The source file is **never modified**. If repair is required, the
tool works on a copy (created via `--work-on-copy` in the programmatic
API; the CLI itself only reports).

## Reading damaged files

The reader is tolerant of:

* Truncated last page (zero-padded).
* Item offset table pointing past page bounds (record is skipped,
  counted as `errors`).
* Pages with an invalid `page_type` (silently classified as free
  pages).
* Overflow chains longer than the documented maximum (rejected with
  a controlled error).

## What recovery does NOT do

* It does not repair the source file. The original is left intact.
* It does not "invent" records. Anything we cannot decode is
  reported as corrupted, not silently dropped or faked.
* It does not output decrypted private keys by default. Use
  `export --private-keys --passphrase ...` for that, or look at the
  JSON migration output of `migrate`.

## Interpreting the report

```text
BDB readable          : YES    -- file header parsed, page-size sensible
Wallet records        : FULL   -- every record parsed OK
Master key            : PRESENT -- at least one mkey record
Encrypted keys        : 117    -- count of ckey records seen
Transactions          : 34     -- count of tx records seen
Corrupted records     : 3      -- records that failed to parse
Result                : PARTIALLY RECOVERABLE
```

## Exit codes

`recover` returns:

* `0` (`SUCCESS`) when `Result == OK`
* `5` (`CORRUPTED_WALLET`) when the file is partially recoverable
  or unrecoverable
* `6` (`INCORRECT_PASSPHRASE`) when a passphrase was supplied that
  fails to decrypt any mkey record

## Programmatic API

```cpp
#include "btclegacy/recovery/recover.h"

btclegacy::recovery::RecoveryReport report;
std::string err;
btclegacy::recovery::recover_wallet(
    "/path/to/wallet.dat",
    std::optional<std::string>{"passphrase"},  // or std::nullopt
    /*work_on_copy=*/true,
    report,
    err);
```

This API is used internally by the CLI and is suitable for embedding
into other recovery tooling.
