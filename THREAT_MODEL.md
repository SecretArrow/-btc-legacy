# Threat Model

## Scope

`btc-legacy` is a single-binary, offline, command-line tool for
inspecting, validating, backing up, recovering, and migrating legacy
Bitcoin Core `wallet.dat` files (approximately the 2009–2015 era).

This document describes what `btc-legacy` defends against and what
it does not.

## Assets (what we are trying to protect)

1. **Source wallet files** — never modified during read-only
   operations.
2. **Decrypted private keys** — must not be exposed beyond the
   duration needed to perform the requested operation.
3. **Wallet passphrases** — must not be exposed beyond the duration
   needed to verify or decrypt.
4. **Backups** — must be byte-identical to the source; SHA-256
   verified.

## Trust boundaries

```
+-------------------------------------------+
| User                                      |
|   |                                       |
|   | argv (incl. --passphrase)             |
|   v                                       |
| btc-legacy binary                         |
|   |                                       |
|   | read-only access to wallet.dat       |
|   v                                       |
| Local filesystem (wallet.dat, backups)   |
|   |                                       |
|   | (NO network I/O anywhere)             |
|   v                                       |
| (nothing — no remote call)                |
+-------------------------------------------+
```

There is no remote trust boundary. There is no client/server
communication.

## Adversaries

### Adversary 1: A malicious party with read access to wallet.dat

`btc-legacy` does not "stop" this adversary from reading the wallet.
What it does is:

* Not make the wallet **easier** to attack (no copy, no upload).
* Detect and report whether the wallet is encrypted; if so, the
  adversary still needs the passphrase.
* Not log private keys or passphrases anywhere.

### Adversary 2: A malicious party with read access to the backup

The backup is byte-identical to the source. The adversary gains no
extra information from the backup beyond what they would have from
the source itself.

### Adversary 3: A malicious party with shell history / `ps` access

The `--passphrase "secret"` flag is documented as **dangerous**.
Safer alternatives are: `--passphrase-stdin`, `--passphrase-file`
(with restrictive permissions), or the interactive hidden prompt.
The tool never logs the passphrase.

### Adversary 4: A malicious party with read access to RAM after the
tool exits

The tool:

* Wipes the SecureBuffer holding the passphrase via `volatile memset`.
* Wipes the derived master key.
* Wipes the decrypted private key bytes after producing WIF output.

This is best-effort: it does not defend against swap, core dumps, or
memory squatting by a hostile kernel module.

### Adversary 5: A malicious party who feeds the tool a *crafted*
`wallet.dat`

The tool must not crash on malformed input. The fuzz driver
exercises this property and must complete with **no findings**.

## Non-goals

`btc-legacy` is **not** designed to:

* Recover lost passphrases (it can only verify a candidate passphrase
  against the wallet's `mkey` record).
* Crack AES-256-CBC.
* Detect stealth malware that has already compromised the host.
* Defend against a malicious kernel.
* Defend against cold-boot attacks beyond best-effort memory wiping.

## Operational recommendations

1. Run `btc-legacy` on a dedicated, offline, single-user host.
2. Disable swap (or use encrypted swap).
3. Use the interactive prompt or `--passphrase-stdin` — not
   `--passphrase "secret"`.
4. Move the resulting backup file to encrypted storage immediately.
5. After recovery / migration is complete, securely delete the
   unencrypted destination (e.g. `shred -u /tmp/migrated.json`).
6. Treat the original `wallet.dat` with the same care as you would
   treat cash — anyone with the file and the passphrase has the keys.
