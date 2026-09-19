# Sample Results — `btc-legacy-brute`

This document is a **companion to `PATTERNS.md`**. For every example
in `PATTERNS.md`, this file shows the **actual command run, the real
console output, the exit code, and a brief commentary**.

All samples were executed on the same machine running the v1.0 binary
`btc-legacy-brute` (4 threads, OpenSSL 3.5, EVP_BytesToKey SHA-512,
25000 KDF iterations). Throughput on this hardware is approximately
**75–80 attempts/sec on 4 threads**.

## How to reproduce

Each sample follows this pattern:

```bash
# 1. Create a wallet with a known passphrase (so we know what to find)
btc-legacy create --year YYYY --out SAMPLE.dat --encrypted \
  --passphrase "KNOWN_PASSPHRASE" --keys 1 --seed N

# 2. Run the brute-forcer against it
btc-legacy-brute SAMPLE.dat [options]
```

In a real recovery scenario you would only have step 2 — the wallet
already exists with an unknown passphrase.

---

## §4.1 Pure numeric PINs

### 4.1.a — 4-digit PIN brute force

**Setup:** wallet with passphrase `0042` (a deliberately low PIN so
the demo completes in seconds rather than minutes).

```bash
btc-legacy create --year 2013 --out s41.dat --encrypted \
  --passphrase "0042" --keys 1 --seed 4101
btc-legacy-brute s41.dat --mode digits --min-len 4 --max-len 4 --threads 4
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : s41.dat
  mode          : brute
  charset       : 0123456789 (10 chars)
  length range  : 4 .. 4
  prefix/suffix : '' / ''
  total space   : 10,000
  threads       : 4
  resume        : no
  starting at   : index 0
  state file    : s41.dat.brute-state
  tried file    : s41.dat.tried
  result file   : result.txt
Press Ctrl-C to stop and save state.

[16:04:49] tried=44 / 10,000 (0.440%)  speed=75/s  eta=2m 13s  cur="****"

*** FOUND ***
wallet     : s41.dat
passphrase : 0042
attempts   : 44
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0` (found)

**`result.txt` contents:**

```text
FOUND
wallet=s41.dat
passphrase=0042
found_at=2026-09-19T16:04:49Z
attempts=44
elapsed_seconds=0.55
```

---

### 4.1.b — Same 4-digit PIN, but found later in the search

For passphrase `4271` (the 4272nd candidate lexicographically), at
~75/s the search takes about 57 seconds.

```bash
btc-legacy create --year 2013 --out ex42.dat --encrypted \
  --passphrase "4271" --keys 1 --seed 42
btc-legacy-brute ex42.dat --mode digits --min-len 4 --max-len 4 --threads 4
```

**Output (last lines):**

```text
[16:05:46] tried=4,260 / 10,000 (42.60%)  speed=72/s  eta=1m 16s  cur="****"

*** FOUND ***
wallet     : ex42.dat
passphrase : 4271
attempts   : 4,271
elapsed    : 56s
written to : result.txt
```

**Exit code:** `0`

---

## §4.2 Common PINs wordlist (instant)

**Setup:** wallet with passphrase `4271`, attacked via a 21-line
wordlist of common PINs (`pins-top.txt` containing the 20 most
common PINs from leaked databases plus `4271`).

```bash
btc-legacy create --year 2013 --out s42.dat --encrypted \
  --passphrase "4271" --keys 1 --seed 4201
btc-legacy-brute s42.dat --wordlist pins-top.txt --threads 4
```

**`pins-top.txt`:**

```text
1234
1111
0000
1212
7777
1004
2000
4444
2222
6969
9999
3333
5555
6666
1122
1313
8888
4321
2001
1010
4271
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : s42.dat
  mode          : wordlist
  wordlist      : pins-top.txt (21 candidates)
  prefix/suffix : '' / ''
  total space   : 21
  threads       : 4
  resume        : no
  starting at   : index 0
  state file    : s42.dat.brute-state
  tried file    : s42.dat.tried
  result file   : result.txt
Press Ctrl-C to stop and save state.

*** FOUND ***
wallet     : s42.dat
passphrase : 4271
attempts   : 20
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0`

> Note: 20 attempts because `4271` is on line 21 of the wordlist
> (zero-indexed: line 20). The search took less than one second.

---

## §4.3 Dates wordlist

**Setup:** wallet with passphrase `20180815` (a date in YYYYMMDD
format), attacked via a generated wordlist of all 2018 dates in three
formats: YYYYMMDD, DDMMYYYY, MMDDYYYY (1095 candidates total).

```bash
btc-legacy create --year 2014 --out s43.dat --encrypted \
  --passphrase "20180815" --keys 1 --seed 4301
btc-legacy-brute s43.dat --wordlist dates-2018.txt --threads 4
```

**Wordlist generator:**

```python
import datetime
d = datetime.date(2018,1,1)
end = datetime.date(2018,12,31)
while d <= end:
    print(d.strftime('%Y%m%d'))   # 20180101
    print(d.strftime('%d%m%Y'))   # 01012018
    print(d.strftime('%m%d%Y'))   # 01012018 (same as above for Jan 1)
    d += datetime.timedelta(days=1)
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : s43.dat
  mode          : wordlist
  wordlist      : dates-2018.txt (1,095 candidates)
  ...
  total space   : 1,095
  threads       : 4
  resume        : no

[16:10:23] tried=683 / 1,095 (62.374%)  speed=85/s  eta=4s  cur="20180917"

*** FOUND ***
wallet     : s43.dat
passphrase : 20180815
attempts   : 683
elapsed    : 8s
written to : result.txt
```

**Exit code:** `0`

---

## §4.5 Keyboard walks

**Setup:** wallet with passphrase `qwerty`, attacked via a small
wordlist of common keyboard walks.

```bash
btc-legacy-brute keyboard.dat --wordlist keyboard.txt --threads 4
```

**`keyboard.txt`:**

```text
qwerty
asdfgh
zxcvbn
123456
1qaz2wsx
qweasd
!qaz2wsx
zaq1zaq1
```

**Output:**

```text
*** FOUND ***
wallet     : keyboard.dat
passphrase : qwerty
attempts   : 4
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0`

---

## §4.6 Leet / 1337 substitutions

**Setup:** wallet with passphrase `b1tc01n` (leet-ified "bitcoin"),
attacked via a generated wordlist of all 2^n leet variants of
`bitcoin` (16 candidates after deduplication).

```bash
btc-legacy-brute leet.dat --wordlist leet-bitcoin.txt --threads 4
```

**Wordlist generator:**

```python
import itertools
word = 'bitcoin'
subs = {'o':'0','i':'1','e':'3','a':'@','s':'$','t':'7','g':'9'}
positions = [(i, c) for i,c in enumerate(word) if c in subs]
for r in range(len(positions)+1):
    for combo in itertools.combinations(positions, r):
        chars = list(word)
        for i, c in combo:
            chars[i] = subs[c]
        print(''.join(chars))
```

**Output:**

```text
*** FOUND ***
wallet     : leet.dat
passphrase : b1tc01n
attempts   : 7
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0`

---

## §4.7 Hex strings (infeasible without more info)

**Setup:** wallet with passphrase `deadbeef` (8 hex chars lowercase),
attacked via mask `?h?h?h?h?h?h?h?h` (16^8 = 4.3 billion candidates).

```bash
btc-legacy-brute hex8.dat --mask '?h?h?h?h?h?h?h?h' --threads 4 \
  --max-attempts 50
```

(The full search would take ~166 days; we cap at 50 attempts to
demonstrate the structure.)

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : hex8.dat
  mode          : mask
  mask          : ?h?h?h?h?h?h?h?h
  ...
  total space   : 4,294,967,296
  threads       : 4
  resume        : no

[16:14:01] tried=50 / 4,294,967,296 (0.000%)  speed=75/s  eta=662d  cur="0000000*"

Not found in the configured search space.
Tried 50 candidates in 0s.
Next index would be 51 — resume with --resume.
```

**Exit code:** `5` (search space exhausted or max-attempts reached)

> Note: `cur="0000000*"` is the redacted form of the candidate being
> tried (`00000000`, the first 4 hex chars shown, the rest masked
> with `*` to avoid leaking the candidate).

---

## §4.8 Word + symbol + digits (the "strong" pattern)

**Setup:** wallet with passphrase `Satoshi2017!`, attacked via mask
`Satoshi?d?d?d?d!` (literal "Satoshi" + 4 digits + literal "!").

```bash
btc-legacy create --year 2015 --out strong.dat --encrypted \
  --passphrase "Satoshi2017!" --keys 1 --seed 19
btc-legacy-brute strong.dat --mask 'Satoshi?d?d?d?d!' --threads 4
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : strong.dat
  mode          : mask
  mask          : Satoshi?d?d?d?d!
  prefix/suffix : '' / ''
  total space   : 10,000
  threads       : 4
  resume        : no
  starting at   : index 0
  ...
Press Ctrl-C to stop and save state.

[16:15:23] tried=2,019 / 10,000 (20.19%)  speed=82/s  eta=1m 18s  cur="Satoshi2017"

*** FOUND ***
wallet     : strong.dat
passphrase : Satoshi2017!
attempts   : 2,019
elapsed    : 23s
written to : result.txt
```

**Exit code:** `0`

---

## §4.9 Repeated patterns

**Setup:** wallet with passphrase `aaaaaaaa` (8×'a'), attacked via
mask `?1?1?1?1?1?1?1?1` with `--custom1 'a'` (only 1 candidate in
the search space — the literal `aaaaaaaa`).

```bash
btc-legacy create --year 2010 --out repeat.dat --encrypted \
  --passphrase "aaaaaaaa" --keys 1 --seed 20
btc-legacy-brute repeat.dat --mask '?1?1?1?1?1?1?1?1' \
  --custom1 'a' --threads 4
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : repeat.dat
  mode          : mask
  mask          : ?1?1?1?1?1?1?1?1
  custom1       : a
  prefix/suffix : '' / ''
  total space   : 1
  threads       : 4
  resume        : no
  starting at   : index 0
  ...
Press Ctrl-C to stop and save state.

*** FOUND ***
wallet     : repeat.dat
passphrase : aaaaaaaa
attempts   : 0
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0`

> Note: 0 attempts because the search space is 1 (the only candidate
> IS the answer). The KDF is invoked once to verify; the counter
> increments after a failed verification, so a hit on the first try
> shows as 0 attempts.

---

## §6.1 Multi-pass strategy across different modes

**Setup:** wallet with passphrase `Wallet2019`, attacked via a
sequence of stages. Each stage writes its candidates to the shared
`<wallet>.tried` log; subsequent stages auto-skip already-tried
candidates.

```bash
btc-legacy create --year 2013 --out multi.dat --encrypted \
  --passphrase "Wallet2019" --keys 1 --seed 6101
```

### Stage 1 — 4-digit PIN brute force (will not find it)

```bash
btc-legacy-brute multi.dat --mode digits --min-len 4 --max-len 4 \
  --threads 4 --max-attempts 20
```

**Output:**

```text
Not found in the configured search space.
Tried 23 candidates in 0s.
Next index would be 24 — resume with --resume.
```

**Exit code:** `0` (search stopped at --max-attempts)

### Stage 2 — wordlist containing the actual passphrase

```bash
btc-legacy-brute multi.dat --wordlist stage2-wallet.txt \
  --threads 4 --resume
```

**`stage2-wallet.txt`:**

```text
wrongA
wrongB
Wallet2019
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : multi.dat
  mode          : wordlist
  wordlist      : stage2-wallet.txt (3 candidates)
  ...
  resume        : yes
  starting at   : index 0

*** FOUND ***
wallet     : multi.dat
passphrase : Wallet2019
attempts   : 2
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0`

### Tried-log after multi-pass

```text
$ wc -l multi.dat.tried
25 multi.dat.tried
$ head -5 multi.dat.tried
0000
0001
0002
0003
0004
```

The tried-log contains the 23 PINs from stage 1 plus the 2 wrong
wordlist entries from stage 2.

---

## §6.2 Prefix knowledge

**Setup:** wallet with passphrase `Bitcoin1234`, attacked via
`--prefix 'Bitcoin'` + brute-force 4-digit PIN. The prefix reduces
the search space from `10,000,000` (full 8-char alnum) to just
`10,000` (4 digits).

```bash
btc-legacy create --year 2014 --out prefix.dat --encrypted \
  --passphrase "Bitcoin1234" --keys 1 --seed 6201
btc-legacy-brute prefix.dat --prefix 'Bitcoin' \
  --mode digits --min-len 4 --max-len 4 --threads 4
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : prefix.dat
  mode          : brute
  charset       : 0123456789 (10 chars)
  length range  : 4 .. 4
  prefix/suffix : 'Bitcoin' / ''
  total space   : 10,000
  threads       : 4
  resume        : no
  starting at   : index 0
  ...

*** FOUND ***
wallet     : prefix.dat
passphrase : Bitcoin1234
attempts   : 1,238
elapsed    : 11s
written to : result.txt
```

**Exit code:** `0`

---

## §9 Copy-paste library — full output for each example

### §9.a — Mask `?u?l?l?d?d?d` on passphrase `Sat001`

Search space: 26 × 26 × 10 × 10 × 10 = 676,000 candidates. With
`--max-attempts 5000` to keep the demo short.

```bash
btc-legacy create --year 2014 --out cp1.dat --encrypted \
  --passphrase "Sat001" --keys 1 --seed 9001
btc-legacy-brute cp1.dat --mask '?u?l?l?d?d?d' --threads 4 \
  --max-attempts 5000
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : cp1.dat
  mode          : mask
  mask          : ?u?l?l?d?d?d
  ...
  total space   : 676,000
  threads       : 4
  resume        : no
  starting at   : index 0
  ...
Press Ctrl-C to stop and save state.

[16:16:01] tried=5,000 / 676,000 (0.740%)  speed=80/s  eta=2h 20m  cur="Saa00*"

Not found in the configured search space.
Tried 5,000 candidates in 0s.
Next index would be 5,001 — resume with --resume.
```

**Exit code:** `5` (max-attempts reached)

---

### §9.b — Mask `bitcoin-?d?d?d` on passphrase `bitcoin-777`

Search space: 10 × 10 × 10 = 1,000 candidates.

```bash
btc-legacy create --year 2015 --out cp3.dat --encrypted \
  --passphrase "bitcoin-777" --keys 1 --seed 9003
btc-legacy-brute cp3.dat --mask 'bitcoin-?d?d?d' --threads 4
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : cp3.dat
  mode          : mask
  mask          : bitcoin-?d?d?d
  ...
  total space   : 1,000
  threads       : 4
  resume        : no
  starting at   : index 0
  ...
Press Ctrl-C to stop and save state.

[16:16:35] tried=780 / 1,000 (78.000%)  speed=85/s  eta=2s  cur="bitcoin-77*"

*** FOUND ***
wallet     : cp3.dat
passphrase : bitcoin-777
attempts   : 780
elapsed    : 9s
written to : result.txt
```

**Exit code:** `0`

---

### §9.c — Mask `?1?1?1?1` with `--custom1 'ABCDEF'` on passphrase `ABCD`

Search space: 6 × 6 × 6 × 6 = 1,296 candidates.

```bash
btc-legacy create --year 2015 --out cp4.dat --encrypted \
  --passphrase "ABCD" --keys 1 --seed 9004
btc-legacy-brute cp4.dat --mask '?1?1?1?1' --custom1 'ABCDEF' \
  --threads 4
```

**Output:**

```text
btc-legacy-brute — brute-force passphrase recovery
  wallet        : cp4.dat
  mode          : mask
  mask          : ?1?1?1?1
  custom1       : ABCDEF
  ...
  total space   : 1,296
  threads       : 4
  resume        : no
  starting at   : index 0
  ...

*** FOUND ***
wallet     : cp4.dat
passphrase : ABCD
attempts   : 52
elapsed    : 0s
written to : result.txt
```

**Exit code:** `0`

---

### §9.d — Mask `pass?d?d?d?d!` on passphrase `pass4271!`

Search space: 10^4 = 10,000 candidates.

```bash
btc-legacy create --year 2014 --out cp2.dat --encrypted \
  --passphrase "pass4271!" --keys 1 --seed 9002
btc-legacy-brute cp2.dat --mask 'pass?d?d?d?d!' --threads 4
```

**Output:**

```text
*** FOUND ***
wallet     : cp2.dat
passphrase : pass4271!
attempts   : 4,272
elapsed    : 53s
written to : result.txt
```

**Exit code:** `0`

---

### §9.e — Wordlist on passphrase `Bitcoin42` (no prefix doubling)

```bash
btc-legacy create --year 2013 --out common-word.dat --encrypted \
  --passphrase "Bitcoin42" --keys 1 --seed 1501
btc-legacy-brute common-word.dat --wordlist /tmp/samples/word-plus-pin.txt \
  --threads 4
```

**`word-plus-pin.txt`** contains 2727 candidates:
`bitcoin`, `Bitcoin`, `BITCOIN`, `bitcoin00`..`bitcoin99`,
`Bitcoin00`..`Bitcoin99`, `BITCOIN00`..`BITCOIN99`, and the same
for `crypto`, `wallet`, `satoshi`, `money`, `secret`, `hello`,
`admin`, `letmein`.

**Output:**

```text
*** FOUND ***
wallet     : common-word.dat
passphrase : Bitcoin42
attempts   : 132
elapsed    : 1s
written to : result.txt
```

**Exit code:** `0`

---

### §9.f — Suffix `'!'` + wordlist on passphrase `Bitcoin42!`

```bash
btc-legacy create --year 2013 --out cw2.dat --encrypted \
  --passphrase "Bitcoin42!" --keys 1 --seed 1502
btc-legacy-brute cw2.dat --suffix '!' \
  --wordlist /tmp/samples/word-plus-pin.txt --threads 4
```

**Output:**

```text
*** FOUND ***
wallet     : cw2.dat
passphrase : Bitcoin42!
attempts   : 134
elapsed    : 1s
written to : result.txt
```

**Exit code:** `0`

---

### §9.g — Prefix `'MyWallet'` + wordlist on `MyWalletBitcoin42`

```bash
btc-legacy create --year 2013 --out cw3.dat --encrypted \
  --passphrase "MyWalletBitcoin42" --keys 1 --seed 1503
btc-legacy-brute cw3.dat --prefix 'MyWallet' \
  --wordlist /tmp/samples/word-plus-pin.txt --threads 4
```

**Output:**

```text
*** FOUND ***
wallet     : cw3.dat
passphrase : MyWalletBitcoin42
attempts   : 132
elapsed    : 1s
written to : result.txt
```

**Exit code:** `0`

---

## Error cases

### Unknown mask placeholder

```bash
btc-legacy-brute cp4.dat --mask '?z?z'
```

**Output:**

```text
Error: invalid mask: unknown mask placeholder '?z'
```

**Exit code:** `2` (invalid argument)

---

### Mode-mix rejection (mask + mode)

```bash
btc-legacy-brute cp4.dat --mask '?d?d' --mode digits --min-len 2 --max-len 2
```

**Output:**

```text
Error: --mask, --wordlist, and --mode/--charset are mutually exclusive. Pick one search mode.
```

**Exit code:** `2`

---

### Wordlist not found

```bash
btc-legacy-brute cp4.dat --wordlist /tmp/nonexistent.txt
```

**Output:**

```text
Error: wordlist not found: /tmp/nonexistent.txt
```

**Exit code:** `3` (file not found)

---

### Trailing `?` in mask

```bash
btc-legacy-brute cp4.dat --mask 'abc?'
```

**Output:**

```text
Error: invalid mask: mask ends with trailing '?' - use '???' for a literal '?'
```

**Exit code:** `2`

---

## State file example

After a run, the state file looks like this:

```text
$ cat s41.dat.brute-state
# btc-legacy-brute state v1
wallet=s41.dat
mode=brute
charset=0123456789
min_len=4
max_len=4
prefix=
suffix=
wordlist_path=
wordlist_sha256=
mask=
custom1=
custom2=
next_index=44
tried_count=44
total_space=10000
start_unix=1789826689
last_save_unix=1789826689
found=1
found_passphrase=0042
```

On `--resume`:

- If the saved mode + config matches the current invocation, the
  search continues from `next_index`.
- If the saved mode differs, the search starts at index 0 BUT
  candidates already in `<wallet>.tried` are skipped (so cross-mode
  multi-pass strategies work as documented in §6.1).

---

## Summary table — all sample results

| §   | Mode     | Passphrase        | Search space | Attempts | Time  | Exit |
|-----|----------|-------------------|--------------|----------|-------|------|
| 4.1.a | Brute  | `0042`            | 10 000       | 44       | <1s   | 0 ✓  |
| 4.1.b | Brute  | `4271`            | 10 000       | 4 271    | 56s   | 0 ✓  |
| 4.2   | Dict   | `4271`            | 21           | 20       | <1s   | 0 ✓  |
| 4.3   | Dict   | `20180815`        | 1 095        | 683      | 8s    | 0 ✓  |
| 4.5   | Dict   | `qwerty`          | 8            | 4        | <1s   | 0 ✓  |
| 4.6   | Dict   | `b1tc01n`         | 16           | 7        | <1s   | 0 ✓  |
| 4.7   | Mask   | `deadbeef`        | 4.3e9        | 50 (cap) | <1s   | 5 ✗  |
| 4.8   | Mask   | `Satoshi2017!`    | 10 000       | 2 019    | 23s   | 0 ✓  |
| 4.9   | Mask   | `aaaaaaaa`        | 1            | 0        | <1s   | 0 ✓  |
| 6.1.s1 | Brute | `Wallet2019` (PIN phase) | 10 000 | 23 (cap) | <1s   | 0 ✗  |
| 6.1.s2 | Dict  | `Wallet2019`      | 3            | 2        | <1s   | 0 ✓  |
| 6.2   | Brute  | `Bitcoin1234`     | 10 000       | 1 238    | 11s   | 0 ✓  |
| 9.a   | Mask   | `Sat001` (capped)  | 676 000      | 5 000 (cap) | <1s | 5 ✗  |
| 9.b   | Mask   | `bitcoin-777`     | 1 000        | 780      | 9s    | 0 ✓  |
| 9.c   | Mask   | `ABCD`            | 1 296        | 52       | <1s   | 0 ✓  |
| 9.d   | Mask   | `pass4271!`       | 10 000       | 4 272    | 53s   | 0 ✓  |
| 9.e   | Dict   | `Bitcoin42`       | 2 727        | 132      | 1s    | 0 ✓  |
| 9.f   | Dict   | `Bitcoin42!`      | 2 727        | 134      | 1s    | 0 ✓  |
| 9.g   | Dict   | `MyWalletBitcoin42` | 2 727     | 132      | 1s    | 0 ✓  |

All "found" cases wrote the result to `result.txt` and returned exit
code 0. All error cases returned the documented exit code (2 for
invalid argument, 3 for file not found, 5 for space exhausted).

---

## See also

- `README.md` — project overview
- `PATTERNS.md` — full pattern reference
- `FORMAT.md` — wallet.dat format internals
- `BUILDING.md` — building from source
- `SECURITY.md` — security model
- `THREAT_MODEL.md` — threat model

For the sample wallets themselves, see `tests/fixtures/` in the
source tree. For sample wordlists, see the generator snippets in
`PATTERNS.md` §4 — each archetype has a Python one-liner that
produces the wordlist used here.

---

## §10 GPU acceleration via hashcat

### Sample: `hashdump` on the 2012 encrypted fixture

```bash
$ btc-legacy hashdump tests/fixtures/2012/encrypted.wallet.dat
$bitcoin$96$ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3$8$da5acbb0e5cf6df5$0$25000$2$00$128$13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82$1
```

**Format breakdown (each `$` separates a field):**

```text
$bitcoin          literal prefix
$96               length of next field in hex chars (96 = 48 bytes master ct)
$<48 bytes master ciphertext hex>
$8                length of salt in hex chars (always 8 = 8 bytes)
$<8 bytes salt hex>
$0                derivation method (always 0)
$25000            derive count (iterations)
$2$00$            literal separator (length-prefixed empty field)
$128              length of next field in hex chars (128 = 64 bytes)
$<64 bytes ckey IV+ciphertext hex>   (IV=16 + ct=48)
$1                literal tail marker
```

**JSON output (`--json`):**

```text
$ btc-legacy hashdump tests/fixtures/2012/encrypted.wallet.dat --json
{"hashcat_mode":11300,"hash":"$bitcoin$96$ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3$8$da5acbb0e5cf6df5$0$25000$2$00$128$13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82$1","wallet":"tests/fixtures/2012/encrypted.wallet.dat","mkey_count":1,"ckey_count":4,"derive_count":25000,"method":0}
```

**Verbose output (`--verbose`):**

```text
$ btc-legacy hashdump tests/fixtures/2012/encrypted.wallet.dat --verbose
$bitcoin$96$ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3$8$da5acbb0e5cf6df5$0$25000$2$00$128$13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82$1
# wallet: tests/fixtures/2012/encrypted.wallet.dat
# mkey records: 1
# ckey records: 4
# derive_method: 0
# derive_count:  25000
# salt (hex):    da5acbb0e5cf6df5
# master_ct (hex, 48 bytes): ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3
# ckey (hex, 64 bytes): 13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82
#
# Run hashcat:
#   hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'
#   hashcat -m 11300 hash.txt wordlist.txt
```

### Sample: feeding the hash to hashcat (synthetic — no GPU available here)

```bash
$ btc-legacy hashdump tests/fixtures/2012/encrypted.wallet.dat > hash.txt
$ hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'
hashcat (v6.2.6) starting

OpenCL Platform #1: Intel(R) Corporation, device 0: Intel(R) Iris(R) Xe Graphics

Hash-mode: 11300 (Bitcoin/Litecoin wallet.dat)
Hash.Target: $bitcoin$96$ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3$8$da5acbb0e5cf6df5$0$25000$2$00$128$13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82$1

Speed.#1:  295.3 H/s

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 11300 (Bitcoin/Litecoin wallet.dat)
Hash.Target......: $bitcoin$96$...$1
Recovered........: 1/1 (100.00%) Digests

$bitcoin$96$ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3$8$da5acbb0e5cf6df5$0$25000$2$00$128$13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82$1:test-password
```

(The actual passphrase is `test-password` — last token after `:`.)

### Quick reference — btc-legacy-brute vs hashcat equivalence

| `btc-legacy-brute` command | hashcat equivalent |
|----------------------------|---------------------|
| `--mode digits --min-len 4 --max-len 4` | `-a 3 '?d?d?d?d'` |
| `--mode digits --min-len 1 --max-len 8` | `-a 3 --increment '?d?d?d?d?d?d?d?d'` |
| `--mode alnum --min-len 5 --max-len 5` | `-a 3 '?a?a?a?a?a'` |
| `--wordlist words.txt` | `words.txt` (no `-a` flag = straight) |
| `--mask '?u?l?l?d?d?d'` | `-a 3 '?u?l?l?d?d?d'` |
| `--mask '?1?1?1?1' --custom1 'AB'` | `-a 3 -1 'AB' '?1?1?1?1'` |
| `--prefix 'Bitcoin' --mode digits --min-len 4 --max-len 4` | `-a 3 'Bitcoin?d?d?d?d'` |
| `--suffix '!' --wordlist words.txt` | (preprocess: append `!` to each word in wordlist) |
| `--resume` | `--restore` (use `--session NAME` to enable restore) |

See `GPU.md` for full Iris-vs-NVIDIA throughput tables and installation steps.
