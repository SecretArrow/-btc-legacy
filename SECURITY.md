# Security Policy

## Reporting vulnerabilities

Please open a private issue or contact the maintainers directly. Do
not file a public issue for security-relevant bugs.

## Threat model (summary)

`btc-legacy` is designed to operate on **wallets that you own or are
authorized to inspect**, **completely offline**, with **no telemetry**
and **no network access**. See `THREAT_MODEL.md` for details.

## Things `btc-legacy` deliberately does NOT do

* No network functionality.
* No telemetry, analytics, or "phone-home" code.
* No upload of wallet files, private keys, or passphrases.
* No "wallet.dat theft", remote wallet collection, malware, or
  hidden key extraction.
* No automatic modification of the source wallet file during read,
  inspect, validate, recover, or migrate.
* No storage of passphrases in configuration files, logs, or JSON output.
* No reliance on cloud services for any operation.

## Passphrase handling

The passphrase entered by the user is held in a `SecureBuffer`
(`platform::SecureBuffer`) which:

* Attempts to `mlock()` the underlying pages (best-effort; failure
  is non-fatal on systems where mlock is unavailable).
* Zeroes the buffer with a `volatile memset` on destruction.
* Wipes intermediate plaintext material (e.g. the decrypted master
  key) immediately after use.

After verification, the passphrase is wiped from the `std::string`
copy via `platform::secure_wipe`.

> **Operational warning**: `--passphrase "secret"` on the command
> line leaks the secret through shell history, `ps` output, CI logs,
> and command auditing. The tool supports safer alternatives
> (`--passphrase-file`, `--passphrase-stdin`, interactive prompt).
> Prefer those whenever possible.

## What this tool cannot protect against

* A compromised host (keylogger, malware, ptrace, etc.) can capture
  the passphrase, the master key, and all decrypted private keys.
* A cold-recovery attack on the swap partition can recover wiped
  memory if the kernel swaps pages before they are wiped. (Mitigation:
  run `btc-legacy` on a system with swap disabled or encrypted.)
* A forensic examination of the source `wallet.dat` file (e.g. an
  attacker who already has read access to the file) is not "stopped"
  by this tool — the tool just doesn't make matters worse by leaking
  more material.

## Build hardening

The default build enables `-Wall -Wextra -Wpedantic -Wshadow
-Wconversion -Wformat=2 -Werror`. Optional ASan + UBSan builds
are supported (`-DBTC_LEGACY_ASAN=ON -DBTC_LEGACY_UBSAN=ON`).

The fuzz driver (`build/btc-legacy-fuzz`) runs mutations against the
BDB reader, wallet record parsers, and passphrase verification path
and must complete with no findings.
