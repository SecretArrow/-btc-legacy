# Pattern Reference — `btc-legacy-brute`

This document is the **complete pattern cookbook** for `btc-legacy-brute`.
It covers every placeholder, every search mode, common password
archetypes you will encounter in real Bitcoin wallets, time-to-search
estimates, and a recommended **strategy decision tree** for ordering
attacks from cheapest to most expensive.

The tool re-implements Bitcoin Core's `CCrypter` KDF
(`EVP_BytesToKey` with `SHA-512` and `25000` iterations per attempt),
which is **CPU-bound** — expect roughly:

| Setup                                  | Attempts/sec |
|----------------------------------------|--------------|
| 1 thread, modern x86_64                | ~70–100 /s    |
| 4 threads                              | ~280–400 /s   |
| 8 threads                              | ~500–700 /s   |
| 16 threads                             | ~900–1200 /s  |

Keep these numbers in mind when reading the time-estimate tables below.

---

## 1. Quick reference card

```
SEARCH MODES (pick exactly one per run)
─────────────────────────────────────────────────────────────────────────
Mode A — Brute force  (default)
        --mode <preset>           digits | lower | upper | alpha
                                   | alnum | hex | hexu | all | custom
        --charset <chars>         overrides --mode (literal charset)
        --min-len N --max-len N   inclusive length range

Mode B — Dictionary
        --wordlist <path>         one candidate per line

Mode C — Mask attack
        --mask <pattern>          pattern with placeholders (see §2)
        --custom1 <chars>         charset for ?1
        --custom2 <chars>         charset for ?2

COMMON (apply to all modes)
  --prefix <str>                  prepended to every candidate
  --suffix <str>                   appended to every candidate
  --threads N                     default = hardware concurrency
  --resume / --no-resume          continue from saved state
  --max-attempts N                bail out after N tries
  --json / --quiet                output control

OUTPUT FILES
  <wallet>.brute-state            auto-saved resume state
  <wallet>.tried                  append-only log of tried candidates
  result.txt                      where the found passphrase is written
```

---

## 2. Mask placeholder syntax

A `--mask PATTERN` is a string that mixes **literal characters** with
**placeholders**. Each placeholder expands to a charset; the search
space is the product of all placeholder charsets.

| Placeholder | Charset                                      | Count |
|-------------|----------------------------------------------|-------|
| `?d`        | `0123456789`                                  | 10    |
| `?l`        | `abcdefghijklmnopqrstuvwxyz`                  | 26    |
| `?u`        | `ABCDEFGHIJKLMNOPQRSTUVWXYZ`                  | 26    |
| `?s`        | `!@#$%^&*()_+-=[]{}|;:,.<>?/~` + space        | 32    |
| `?a`        | `?l` + `?u` + `?d`                            | 62    |
| `?h`        | `0123456789abcdef`                            | 16    |
| `?H`        | `0123456789ABCDEF`                            | 16    |
| `?1`        | value of `--custom1 STRING`                  | any   |
| `?2`        | value of `--custom2 STRING`                  | any   |
| `??`        | literal `?` (escape)                         | 1     |
| any other char | literal character                          | 1     |

### Escape rules

- `?` is **always** the start of a placeholder unless escaped as `??`.
- To produce a literal `pass?word`, write `pass??word`.
- A mask that ends with a bare `?` is rejected (use `??`).
- Unknown placeholders (e.g. `?z`) are rejected up-front.
- `--custom1` / `--custom2` are **required** if the mask uses `?1` / `?2`;
  the tool will refuse to run otherwise.

### Iteration order

For a mask like `?d?l`, iteration is:

```
0a 0b 0c ... 0z 1a 1b ... 1z ... 9a 9b ... 9z
```

The rightmost placeholder varies fastest. This makes resume exact:
saving `next_index` is sufficient to continue.

---

## 3. Pattern construction rules

A pattern is built from one or more **slots**, each either:

- A **literal run** of zero or more characters, OR
- A **placeholder** expanding to a charset.

Examples:

| Pattern                | Explanation                                       | Search space        |
|------------------------|---------------------------------------------------|---------------------|
| `?d?d?d?d`             | 4-digit PIN                                        | 10 000              |
| `?l?l?l?l?l?l`         | 5 lowercase letters                                | 11 881 376          |
| `?u?l?l?l?d?d?d?d`     | Capitalized 3-letter word + 4-digit suffix         | 17 576 000          |
| `Bitcoin?d?d?d?d`      | Literal "Bitcoin" + 4-digit PIN                    | 10 000              |
| `pass?d?d?d?d!`        | "pass" + 4 digits + literal "!"                    | 10 000              |
| `?1?1?1?1` (custom1=ABCDEF) | 4 chars from {A,B,C,D,E,F}                    | 1 296               |
| `?h?h?h?h?h?h?h?h`     | 8 hex chars (lowercase) (e.g. an MD5 fragment)     | 16^8 = 4.29e9       |
| `wallet-?d?d?d`        | "wallet-" + 3 digits                               | 1 000               |
| `?u?l?l?l?l?l?l?d?d`   | Cap first + 6 lowercase + 2 digits (common human pattern) | 308 915 776 |

### Choosing charsets wisely

When you don't know whether a character is upper, lower, or digit,
`?a` is the safe catch-all — but the search space grows fast.
Use `?l` / `?u` / `?d` separately if you have evidence.

For wallets you suspect came from a brain-wallet-style password:
- Commonly alphanumeric without symbols → `?a` is fine
- Likely includes the user's name → use prefix `--prefix 'John' --mask '?d?d?d?d'`
- Likely a hex string (e.g. partial seed backup) → `?h` or `?H`

---

## 4. Common password archetypes

The following are the **patterns most often seen in leaked password
dumps** and in user self-reported Bitcoin wallet passphrases. They
should be tried in roughly the order listed here (cheapest first).

### 4.1 Pure numeric PINs

```
--mode digits --min-len 1 --max-len 8            # brute force, 10^1 + ... + 10^8
--mask '?d?d?d?d'                                # explicit 4-digit PIN
--mask '?d?d?d?d?d?d'                            # explicit 6-digit PIN
```

**Time estimate (4 threads, ~300/s):**

| Length | Space   | Time       |
|--------|---------|------------|
| 4      | 10 000  | ~30 s       |
| 5      | 100 000 | ~5 m        |
| 6      | 10^6    | ~55 m       |
| 7      | 10^7    | ~9 h        |
| 8      | 10^8    | ~92 h (~4 days) |

### 4.2 Common 4-digit PINs first (instant)

If you suspect a 4-digit PIN, try the most common ones manually
before launching a full sweep. From public leak statistics, the top 20
account for ~27% of all PINs:

```
1234  1111  0000  1212  7777  1004  2000  4444  2222  6969
9999  3333  5555  6666  1122  1313  8888  4321  2001  1010
```

Easiest: write these to a tiny wordlist and run dictionary mode:

```bash
cat > /tmp/pins-top.txt <<EOF
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
EOF
btc-legacy-brute wallet.dat --wordlist /tmp/pins-top.txt
```

### 4.3 Dates (birthday, anniversary, year)

Human-chosen passphrases very often encode a meaningful date.
Use these patterns:

| Pattern                | Meaning                                   | Space  |
|------------------------|-------------------------------------------|--------|
| `?d?d?d?d`             | 4-digit year (1900–2099 realistic)        | 10 000  |
| `?d?d?d?d?d?d`         | YYMMDD or MMDDYY or DDMMYY                | 10^6   |
| `?d?d?d?d?d?d?d?d`     | YYYYMMDD or MMDDYYYY                       | 10^8   |

To narrow further, you can combine `--prefix` for a known year with
a small mask for the rest:

```bash
# Try every MMDD combination for year 2018
btc-legacy-brute wallet.dat --prefix '2018' --mode digits --min-len 4 --max-len 4
```

Or pre-build a candidate list:

```bash
# All dates 1950-01-01 .. 2025-12-31 (≈ 27 000 candidates)
python3 -c "
import datetime
d = datetime.date(1950,1,1)
end = datetime.date(2025,12,31)
while d <= end:
    print(d.strftime('%Y%m%d')); print(d.strftime('%d%m%Y')); print(d.strftime('%m%d%Y'))
    d += datetime.timedelta(days=1)
" > /tmp/dates.txt

btc-legacy-brute wallet.dat --wordlist /tmp/dates.txt --threads 8
```

### 4.4 Common short words + numbers

Most human passwords are `<word><digits>` or `<Word><digits>`. A
short English-word dictionary (top ~1000 words) crossed with a
4-digit suffix covers a huge fraction of leaked passwords.

```bash
# Build a combined list from a small word file + every 4-digit PIN
python3 -c "
words = open('/tmp/words-1000.txt').read().split()
pins  = [f'{n:04d}' for n in range(10000)]
capwords = [w.capitalize() for w in words]
UPPER = [w.upper() for w in words]
for w in capwords + words + UPPER:
    for p in pins:
        print(w + p)
" > /tmp/word-plus-pin.txt

btc-legacy-brute wallet.dat --wordlist /tmp/word-plus-pin.txt --threads 8
```

(10M candidates — about 6 hours on 4 threads.)

### 4.5 Keyboard walks

Walks along a keyboard row are surprisingly common. They are hard
to express as a mask but easy as a small wordlist:

```
qwerty
asdfgh
zxcvbn
123456
qwertyuiop
asdfghjkl
1qaz2wsx
qweasd
!qaz2wsx
zaq1zaq1
```

Save to `keyboard.txt` and use `--wordlist`.

### 4.6 Leet / 1337 substitutions

If you suspect the passphrase is a leet-ified word, generate variants
yourself and feed them as a wordlist:

```bash
python3 -c "
import itertools
word = 'bitcoin'
subs = {'o':'0','i':'1','e':'3','a':'@','s':'\$','t':'7','g':'9'}
positions = [(i, c) for i,c in enumerate(word) if c in subs]
# Generate all 2^n leet variants
for r in range(len(positions)+1):
    for combo in itertools.combinations(positions, r):
        chars = list(word)
        for i, c in combo:
            chars[i] = subs[c]
        print(''.join(chars))
" > /tmp/leet-bitcoin.txt
btc-legacy-brute wallet.dat --wordlist /tmp/leet-bitcoin.txt
```

### 4.7 Hex strings (partial seed, key fragment)

Some users store a fragment of a seed phrase or a hash as their
passphrase. Try hex masks:

```
--mask '?h?h?h?h?h?h?h?h'           # 8 hex chars lowercase (e.g. half of an MD5)
--mask '?H?H?H?H?H?H?H?H'           # 8 hex chars uppercase
--mask '?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h'  # 16 hex chars
```

| Length | Space         | Time (4 threads) |
|--------|---------------|------------------|
| 8      | 4.3 × 10^9    | ~99 days          |
| 12     | 2.8 × 10^14   | infeasible        |
| 16     | 1.8 × 10^19   | infeasible        |

**Realistic only for ≤8 chars.**

### 4.8 Word + symbol + digits (the "strong" pattern)

If the user followed generic password advice, the passphrase looks
like `<Word>!<digits>` or `<Word>?<digits>!`. Examples:

```
--mask 'Password?d?d?d?d!'           # literal "Password" + 4 digits + "!"
--mask '?u?l?l?l?l?l?l!?d?d?d?d'     # CapWord + "!" + 4 digits
--mask '?u?l?l?l?l?l?l?l?d?d?d?d?s'  # Cap7Word + 4 digits + 1 symbol
```

These spaces get expensive fast; only attempt if cheaper options
failed AND you have additional evidence (e.g. user remembers the
word).

### 4.9 Repeated patterns

Wallets created by users who typed the same character repeatedly:

```
--mask '?1?1?1?1?1?1?1?1' --custom1 'a'   # aaaaaaaa
--mask '?1?1?1?1?1?1?1?1' --custom1 '1'   # 11111111
```

Or build a small wordlist of common repeats:
```
11111111
00000000
aaaaaaaa
password
starwars
letmein
iloveyou
```

---

## 5. Strategy decision tree

When attacking a wallet whose passphrase you don't know, follow this
**order of attempts** — cheapest first. Stop as soon as you find it.

```
1. Common short wordlists (top-1000 passwords + leet variants)
   Cost: minutes to hours, hit-rate: ~30% of real-world passwords

2. Top-N PINs as wordlist (the 20 most common 4-digit PINs)
   Cost: seconds, hit-rate: ~27% of 4-digit PINs

3. Dates wordlist (YYYYMMDD, DDMMYYYY, MMDDYYYY for years 1950..2025)
   Cost: ~5 minutes @ 27k candidates, hit-rate: ~10% of all human passphrases

4. Mask: literal prefix (if known) + short digit run
   e.g. --prefix 'Bitcoin' --mode digits --min-len 4 --max-len 6
   Cost: minutes, hit-rate: depends on prefix guess accuracy

5. Brute-force: digits only, length 1..6 (then 7, then 8 if time permits)
   Cost: 1 hour → 1 day
   Hit-rate: ~5% of remaining

6. Mask: capitalized short word + 3-4 digit suffix
   --mask '?u?l?l?l?d?d?d'   (4-char cap word + 3 digits)
   --mask '?u?l?l?l?l?d?d?d?d' (5-char cap word + 4 digits)
   Cost: ~1 day @ ~300/s, hit-rate: ~15%

7. Mask: ?a length 1..5 (any alphanumeric up to 5 chars)
   Cost: 62^5 = 916M ≈ 35 days @ 300/s
   Hit-rate: residual ~5%

8. Dictionary: large wordlist (rockyou.txt, etc.)
   Cost: hours, hit-rate: high if passphrase came from a leak

9. Brute-force: ?a length 6+ (effectively infeasible — bail)
   62^6 = 56 billion ≈ 5 years @ 300/s
```

### Why this order?

- **Step 1-4** cover the most common human choices in minutes.
- **Step 5** is "just try all PINs up to 8 digits" — relatively fast and
  covers another large chunk.
- **Step 6** covers the `Word+PIN` archetype, the single most common
  pattern in leaked non-PIN passwords.
- **Step 7** is the catch-all for short alphanumeric strings.
- **Step 8** is **only worth it if** you suspect the passphrase came
  from a leaked password database (rockyou, collection #1, etc.).
- **Step 9+** is mathematically infeasible for any reasonably strong
  passphrase; consider BTCRecover or partial-knowledge tools instead.

---

## 6. Combined / multi-pass strategies

### 6.1 Multi-stage attack with shared tried-log

Because every candidate is appended to `<wallet>.tried`, you can run
multiple invocations in sequence and earlier tried candidates will be
auto-skipped:

```bash
# Stage 1: common PINs (top 1000)
btc-legacy-brute wallet.dat --wordlist /tmp/top-pins.txt

# Stage 2: dates
btc-legacy-brute wallet.dat --wordlist /tmp/dates.txt --resume

# Stage 3: 4-digit brute (only candidates not in /tmp/wallet.dat.tried)
btc-legacy-brute wallet.dat --mode digits --min-len 4 --max-len 4 --resume

# Stage 4: cap-word + 3-digit mask
btc-legacy-brute wallet.dat --mask '?u?l?l?l?d?d?d' --resume
```

> Note: the `--resume` flag is what triggers loading of the tried set.
> Without it, each run starts fresh and may re-test candidates.

### 6.2 Prefix knowledge (you remember part of it)

If you remember that the passphrase starts with `Bitcoin`:

```bash
# Try: Bitcoin + 1-6 digits
btc-legacy-brute wallet.dat --prefix 'Bitcoin' --mode digits --min-len 1 --max-len 6

# Try: Bitcoin + 1-4 lowercase letters
btc-legacy-brute wallet.dat --prefix 'Bitcoin' --mode lower --min-len 1 --max-len 4

# Try: Bitcoin + ?! + 4-digit PIN + !?
btc-legacy-brute wallet.dat --prefix 'Bitcoin' --suffix '!' --mode digits --min-len 4 --max-len 4
```

Prefix/suffix apply to ALL three modes (brute / dict / mask).

### 6.3 Combined wordlist + mask (manual)

Want to try every word from a list, each with a 2-digit suffix?
Generate the cross-product yourself and feed as a wordlist:

```bash
python3 -c "
words = open('words.txt').read().split()
for w in words:
    for n in range(100):
        print(f'{w}{n:02d}')
" > /tmp/word-plus-2d.txt
btc-legacy-brute wallet.dat --wordlist /tmp/word-plus-2d.txt --threads 8
```

### 6.4 Parallel multiple CPUs (poor man's cluster)

If you have N machines, you can split a mask attack by giving each
machine a different prefix/suffix range:

```bash
# Machine A: digits 0-4 first
btc-legacy-brute wallet.dat --prefix '0' --mode digits --min-len 4 --max-len 4
btc-legacy-brute wallet.dat --prefix '1' --mode digits --min-len 4 --max-len 4
# Machine B: digits 5-9
btc-legacy-brute wallet.dat --prefix '5' --mode digits --min-len 4 --max-len 4
btc-legacy-brute wallet.dat --prefix '6' --mode digits --min-len 4 --max-len 4
```

(Or just use the tried-log to avoid duplicate work — each machine will
pick up where another left off via the shared NFS-mounted tried file.)

---

## 7. Time-estimate cheat sheet

Assume ~300 attempts/sec (typical 4-thread modern CPU).

| Strategy                                          | Space          | Time          |
|---------------------------------------------------|----------------|---------------|
| Top-20 PINs (wordlist)                            | 20             | < 1 s         |
| All 4-digit PINs (`?d?d?d?d`)                    | 10 000         | ~30 s         |
| All 6-digit PINs (`?d?d?d?d?d?d`)                | 10^6           | ~55 min       |
| All 8-digit PINs                                  | 10^8           | ~92 h (~4 d)  |
| All 4-letter lowercase (`?l?l?l?l`)               | 456 976        | ~25 min       |
| All 5-letter lowercase                            | 11 881 376     | ~11 h         |
| All 6-letter lowercase                            | 308 915 776    | ~12 d         |
| `?u?l?l?l?d?d?d` (Cap4Word+3d)                   | 17 576 000     | ~16 h         |
| `?a` length 1..5                                  | 916 132 832    | ~35 d         |
| `?a` length 6                                     | 56 800 235 584 | ~6 y          |
| Hex 8 (`?h?h?h?h?h?h?h?h`)                        | 4 294 967 296  | ~166 d        |
| Full ASCII 4 chars (`all` charset, 1..4)         | ~82 M          | ~76 h         |
| Full ASCII 5 chars                                | ~7.8 B         | ~300 d        |
| Full ASCII 6 chars                                | ~735 B         | infeasible    |
| rockyou.txt (14.3 M lines)                       | 14 344 391     | ~13 h         |
| Common-passwords-10k                              | 10 000         | ~33 s         |

> "infeasible" = more than ~5 years on the assumed hardware.

---

## 8. Tips for efficiency

1. **Always try cheap attacks first.** A 5-minute wordlist run can
   save days of brute-forcing. See §5.
2. **Use `--prefix`/`--suffix` aggressively** whenever you remember
   any part of the passphrase.
3. **Save state often** (default: every 5 s). A power outage mid-run
   shouldn't cost you hours of work. Use `--state-interval 2` if your
   machine is unstable.
4. **Pin your CPU frequency** (Linux: `cpupower frequency-set -g performance`)
   before launching a long run. Default `powersave` governor can cut
   throughput by 30-50%.
5. **Don't run on a laptop battery** — thermal throttling and battery
   life will both work against you. Plug in.
6. **Multiple machines share via NFS** if `<wallet>.tried` is on a
   shared filesystem. Each machine will pick up untried candidates via
   the atomic index counter; you may have a small overlap (a few
   candidates per machine) due to timing — that's fine.
7. **Skip the tried-set on first run.** If you're starting fresh, pass
   `--no-resume` to avoid the (potentially large) tried-set load.
8. **Use `--json` for scripted runs** so you can parse progress.
9. **Verify with `btc-legacy password verify` after finding** —
   `btc-legacy-brute` uses the same verifier, but double-checking is
   always wise before declaring success.
10. **Don't forget `result.txt` exists.** After a successful run, that
    file contains the passphrase in cleartext. Delete it (use `shred
    -u result.txt` on Linux) once you've noted the passphrase.

---

## 9. Pattern building blocks — copy-paste library

### Pure masks

```bash
# 4-digit PIN
--mask '?d?d?d?d'

# 6-digit PIN
--mask '?d?d?d?d?d?d'

# 8-digit PIN (could be a phone-number-style passphrase)
--mask '?d?d?d?d?d?d?d?d'

# 4 lowercase letters (common short word)
--mask '?l?l?l?l'

# Capitalized 5-letter word + 4-digit PIN
--mask '?u?l?l?l?l?d?d?d?d'

# 8-char hex (MD5 fragment, common in old "importprivkey" patterns)
--mask '?h?h?h?h?h?h?h?h'

# Bitcoin-style: word + dash + 3-digit PIN
--mask 'bitcoin-?d?d?d'

# Word + symbol + 4 digits
--mask 'pass?d?d?d?d!'

# Custom charset: 4 chars from {a,b,c,1,2,3}
--mask '?1?1?1?1' --custom1 'abc123'
```

### Prefix / suffix recipes

```bash
# Known prefix 'MyWallet' + 4-digit PIN
--prefix 'MyWallet' --mode digits --min-len 4 --max-len 4

# Known prefix 'wallet-' + 3 hex chars
--prefix 'wallet-' --mask '?h?h?h'

# Known suffix '!2020' + 6 lowercase letters
--suffix '!2020' --mode lower --min-len 6 --max-len 6

# Both known ends, unknown middle 2 digits
--prefix 'ab' --suffix 'cd' --mode digits --min-len 2 --max-len 2
```

### Wordlist recipes

```bash
# Standard dictionary attack
--wordlist /usr/share/dict/words

# Common leaked passwords
--wordlist rockyou.txt

# Generated date list (see §4.3)
--wordlist /tmp/dates.txt

# Generated cross-product (see §6.3)
--wordlist /tmp/word-plus-2d.txt

# Apply prefix to every word in a list
--prefix 'MyWallet' --wordlist words.txt
```

---

## 10. Anti-patterns — what NOT to do

- **Don't start with `--mode all --max-len 6`.** That's 735 billion
  candidates — ~75 years on a single machine. Always try cheap
  attacks first (see §5).
- **Don't run without `--threads`.** Default is `hardware_concurrency`
  which is usually right, but if you're on a shared box, throttle.
- **Don't mix `--mask` and `--mode`.** The tool rejects it, but
  worth noting: pick exactly one search mode.
- **Don't trust a found result without `btc-legacy password verify`.**
  A corrupted state file could in theory cause a false positive report.
- **Don't store `result.txt` on an unencrypted volume.** Move it to
  encrypted storage or `shred -u` it after noting the passphrase.
- **Don't run on the wallet you're trying to recover while another
  tool has it open for write.** `btc-legacy-brute` opens the wallet
  read-only, but other tools may not.
- **Don't forget to clean up `<wallet>.tried`.** That file leaks every
  candidate you tried (though obviously only the wrong ones). After
  a successful run, delete it: `shred -u wallet.dat.tried`.

---

## 11. Reference: full flag list

```
SEARCH MODE (pick one)
  --mode MODE          brute-force charset preset
  --charset STRING     custom charset (brute-force mode)
  --min-len N          brute-force min length (default 1)
  --max-len N          brute-force max length (required in brute mode)
  --wordlist PATH      dictionary mode
  --mask PATTERN       mask mode
  --custom1 STRING     charset for ?1 placeholder (mask mode)
  --custom2 STRING     charset for ?2 placeholder (mask mode)

COMMON
  --prefix STR         prepend to every candidate
  --suffix STR         append to every candidate
  --threads N          worker threads (default: hardware concurrency)

EXECUTION
  --resume             load saved state and continue
  --no-resume          ignore saved state, start fresh
  --state-file PATH    override state file path
  --state-interval N   save state every N seconds (default 5)
  --tried-file PATH    override tried-log path
  --max-attempts N     bail out after N attempts (0 = unlimited)

OUTPUT
  --result-file PATH   where to write found passphrase (default: result.txt)
  --progress-interval N  progress update every N seconds (default 1)
  --json               JSON progress + result to stdout (no progress bar)
  --quiet              suppress progress display

INFO
  --help, -h           show full help
```

Exit codes (see `--help` for full table):

| 0 | found   | 1 | general error | 2 | invalid argument |
| 3 | not found (file) | 4 | unsupported wallet | 5 | space exhausted |
| 6 | user-interrupted (state saved) |   |   |   |   |

---

## 12. See also

- `README.md` — project overview
- `FORMAT.md` — wallet.dat / mkey / ckey internals
- `SECURITY.md` — security model
- `THREAT_MODEL.md` — what we do and don't defend against
- `BUILDING.md` — building from source

For external resources on real-world password distributions:
- <https://haveibeenpwned.com> — leaked-password lookup
- <https://github.com/danielmiessler/SecLists> — wordlists
- <https://github.com/brannondorsey/naive-hashcat> — mask + rule reference
  (the placeholder syntax in `btc-legacy-brute` mirrors hashcat's, so
  hashcat mask examples translate directly).
