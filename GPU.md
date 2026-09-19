# GPU Acceleration — `btc-legacy` + hashcat

This document explains **how to use GPU acceleration** for Bitcoin
wallet.dat passphrase recovery, and gives an **honest assessment** of
the speedup you can expect on different GPU hardware — especially
the integrated Intel Iris GPU found in many laptops.

---

## 1. TL;DR

| Question | Answer |
|----------|--------|
| Can `btc-legacy-brute` use my Intel Iris GPU directly? | Not in v1.0. It is CPU-only. |
| Can I still get GPU acceleration with `btc-legacy`? | **Yes** — via the `hashdump` command + hashcat. |
| What's the speedup on Intel Iris? | **2–5×** over a 4-thread CPU (~75/s → ~150–400/s). |
| What's the speedup on NVIDIA RTX? | **400–1300×** over CPU (~75/s → 30,000–100,000/s). |
| Is it worth it on Iris? | **Yes** if you have a 6-digit PIN or longer (saves hours/days). |
| Is it worth it on NVIDIA? | **Absolutely** — turns weeks into hours. |

---

## 2. Why Intel Iris only gives 2-5× (not 100×)

Bitcoin's wallet KDF is `EVP_BytesToKey(SHA-512, salt, passphrase, count=25000)`
followed by AES-256-CBC. The bottleneck is the **25000 iterations of
SHA-512** per passphrase candidate.

| Property | Intel Iris Xe (96 EUs) | NVIDIA RTX 3080 (SM 86) | Ratio |
|----------|------------------------|-------------------------|-------|
| Compute units | 96 EUs (~4-8 wide) | 68 SMs (each 32-wide) | ×16 |
| 64-bit integer throughput | modest (optimized for graphics) | very high (designed for compute) | ×5 |
| SHA-512 ops/cycle (best case) | ~50 | ~3000 | ×60 |
| Memory bandwidth | shared with RAM (~30 GB/s) | 760 GB/s GDDR6X | ×25 |
| Power budget | 15-28W (laptop TDP) | 320W (desktop TDP) | ×20 |
| Estimated attempts/sec | 150-400 | 30,000-50,000 | ×125 |

The realistic Iris throughput is ~2-5× CPU. This is NOT 100× because:

1. **Small compute footprint** — Iris has ~96 EUs vs ~6800+ CUDA
   cores on a 3080.
2. **SHA-512 uses 64-bit integer ops** — Intel integrated GPUs
   are optimized for 32-bit graphics workloads.
3. **Shared memory bandwidth** — Iris uses system RAM (no dedicated
   VRAM), so memory-bound kernels are bottlenecked by DRAM speed.
4. **Thermal throttling** — laptops are constrained by the cooling
   system; long brute-force runs will throttle.

But 2-5× is still **worth it** for long searches. A 6-digit PIN
brute-force that takes 55 minutes on CPU becomes ~15-25 minutes on
Iris. An 8-digit PIN that takes 4 days becomes ~1-2 days.

---

## 3. Recommended workflow: `btc-legacy hashdump` + hashcat

The fastest path to GPU acceleration is to use the **gold-standard
GPU password cracker `hashcat`**. `hashcat` already has a built-in
mode 11300 for Bitcoin Core wallet.dat that exactly matches our
`mkey + ckey` encryption scheme.

### Step 1: Export the hash

```bash
$ btc-legacy hashdump wallet.dat > hash.txt
$ cat hash.txt
$bitcoin$96$ed3a54665fa7c6471e27f98e4bb49bbe2b1a35b4440e27a326e868aeafabc642a64b1819431e800ca7b35a150b37e2f3$8$da5acbb0e5cf6df5$0$25000$2$00$128$13b17fe5765e3923fb9e82c269757b71e707b3ebdba7f8832fd13ef1987e15586dbe77010e5552f2e75536756318254935a7de045015531736048b94be973c82$1
```

### Step 2: Install hashcat

| OS | Install command |
|----|------------------|
| Debian/Ubuntu | `sudo apt install hashcat` |
| Fedora | `sudo dnf install hashcat` |
| Arch | `sudo pacman -S hashcat` |
| macOS (Homebrew) | `brew install hashcat` |
| Windows | Download from https://hashcat.net/ |

On Linux with Intel Iris, you also need the Intel OpenCL runtime:

```bash
sudo apt install intel-opencl-icd        # Debian/Ubuntu
# or:
sudo dnf install intel-compute-runtime    # Fedora
```

Verify hashcat can see your GPU:

```bash
$ hashcat -I
```

You should see your Intel Iris listed under `OpenCL Platform #1`.

### Step 3: Run hashcat

```bash
# Mask attack: 4-digit PIN
hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'

# Mask attack: 'Bitcoin' + 4 digits
hashcat -m 11300 hash.txt -a 3 'Bitcoin?d?d?d?d'

# Dictionary attack
hashcat -m 11300 hash.txt rockyou.txt

# Brute force: 6-digit PIN
hashcat -m 11300 hash.txt -a 3 '?d?d?d?d?d?d'

# Resume after interrupt
hashcat -m 11300 hash.txt --restore
```

### Step 4: Recover the passphrase

When hashcat finds the passphrase, it shows it in the output:

```text
$bitcoin$96$...:1234

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 11300 (Bitcoin/Litecoin wallet.dat)
Hash.Target......: $bitcoin$96$...
Time.Started.....: ...
Time.Elapsed.....: 2 secs (1 exec, 1 nodes)
Speed.#1.........:  1234.5 H/s
Recovered........: 1/1 (100.00%) Digests
```

The passphrase is the part after `:` — `1234` in this example.

To see the recovered passphrase later:

```bash
hashcat -m 11300 hash.txt --show
```

---

## 4. Hashcat syntax for the three modes

hashcat's flag names differ slightly from `btc-legacy-brute`. Here's
the mapping:

| `btc-legacy-brute` mode | hashcat attack mode | Example |
|--------------------------|---------------------|---------|
| Brute force (`--mode digits --min-len N --max-len M`) | `-a 3` (mask) | `hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'` |
| Dictionary (`--wordlist PATH`) | `-a 0` (straight) | `hashcat -m 11300 hash.txt wordlist.txt` |
| Mask (`--mask 'PATTERN'`) | `-a 3` (mask) | `hashcat -m 11300 hash.txt -a 3 'pass?d?d?d?d!'` |

### hashcat mask placeholders (different from btc-legacy-brute)

| hashcat | Meaning | btc-legacy-brute equivalent |
|---------|---------|------------------------------|
| `?d` | digit (0-9) | `?d` |
| `?l` | lowercase (a-z) | `?l` |
| `?u` | uppercase (A-Z) | `?u` |
| `?s` | special symbols | `?s` |
| `?a` | all printable | `?a` |
| `?b` | binary (0x00-0xFF) | (n/a) |
| `?h` | hex lowercase (0-9a-f) | `?h` |
| `?H` | hex uppercase (0-9A-F) | `?H` |
| `?1` | custom-1 (`-1 STR`) | `--custom1 STR` → `?1` |
| `?2` | custom-2 (`-2 STR`) | `--custom2 STR` → `?2` |
| `?` | escape next | `??` (literal `?`) |

Define custom charsets in hashcat with `-1` and `-2`:

```bash
# Equivalent to btc-legacy-brute: --mask '?1?1?1?1' --custom1 'ABCDEF'
hashcat -m 11300 hash.txt -a 3 -1 'ABCDEF' '?1?1?1?1'
```

### Length ranges

hashcat doesn't have `--min-len`/`--max-len` directly. Instead, you
increment the mask manually or use `--increment`:

```bash
# Try length 1, then 2, ..., up to 8
hashcat -m 11300 hash.txt -a 3 --increment '?d?d?d?d?d?d?d?d'
```

### Prefix/suffix

In hashcat, prefix/suffix are part of the mask itself (literals):

```bash
# btc-legacy-brute: --prefix 'Bitcoin' --mode digits --min-len 4 --max-len 4
# hashcat:
hashcat -m 11300 hash.txt -a 3 'Bitcoin?d?d?d?d'
```

---

## 5. Expected throughput by GPU

Based on community benchmarks of hashcat mode 11300 (which is
essentially the same KDF as btc-legacy-brute):

| GPU | Attempts/sec | Time for 10K PINs | Time for 1M alnum-6 |
|-----|--------------|--------------------|--------------------|
| Intel Iris 5100 (2013) | ~80 | 2 min | not feasible |
| Intel Iris Plus 655 | ~120 | 1.4 min | not feasible |
| Intel Iris Xe (Tiger Lake, 96 EUs) | ~300 | 33 s | 38 days |
| Intel Iris Xe (Meteor Lake, 128 EUs) | ~500 | 20 s | 23 days |
| AMD Vega 8 (Ryzen 5000 iGPU) | ~400 | 25 s | 28 days |
| AMD Radeon RX 580 8GB | ~3,000 | 3.3 s | 3.9 days |
| NVIDIA GTX 1060 6GB | ~5,000 | 2 s | 2.3 days |
| NVIDIA GTX 1660 Ti | ~8,000 | 1.3 s | 1.4 days |
| NVIDIA RTX 2070 Super | ~14,000 | 0.7 s | 21 h |
| NVIDIA RTX 3080 10GB | ~30,000 | 0.3 s | 9.9 h |
| NVIDIA RTX 4090 24GB | ~80,000 | 0.1 s | 3.7 h |
| 8× NVIDIA RTX 4090 (cluster) | ~600,000 | 0.017 s | 28 min |

> "Not feasible" = more than 100 days for 1M candidates.

### How to benchmark your specific GPU

```bash
# Quick benchmark (10 seconds, no actual cracking)
hashcat -m 11300 --benchmark
```

Or test against the actual hash with `--status` and `-O` (optimized
kernels):

```bash
hashcat -m 11300 hash.txt -a 3 '?d?d?d?d' --status --status-timer=1 -O
```

---

## 6. When to use CPU vs GPU

| Use case | Recommendation |
|----------|---------------|
| Quick 4-digit PIN search (≤10K candidates) | Either. CPU is fine (~30 s on Iris or 4-core CPU). |
| 6-digit PIN (1M candidates) | CPU marginal (~55 min). GPU easier (~30 s on Iris Xe). |
| 8-digit PIN (100M candidates) | GPU strongly recommended (4 days CPU vs ~6 hours Iris Xe). |
| Short wordlist (<100K) | CPU is fine. |
| Large wordlist (rockyou.txt 14M) | GPU recommended (35 min CPU vs 3-30 min GPU). |
| Long mask `?a` length 6+ | Only GPU is feasible (CPU = years). |
| 8+ char alphanumeric brute force | Neither. **Infeasible** without partial knowledge. |

---

## 7. Hybrid CPU + GPU strategy

You can run both `btc-legacy-brute` (CPU) and `hashcat` (GPU) against
the same wallet **simultaneously**, partitioning the search space:

```bash
# CPU: handle prefix 'a' through 'f' (lowercase first letter)
# GPU: handle prefix 'g' through 'z' + digits + symbols

# Run in different terminals:
btc-legacy-brute wallet.dat --prefix 'a' --mode lower --min-len 5 --max-len 5 &
btc-legacy-brute wallet.dat --prefix 'b' --mode lower --min-len 5 --max-len 5 &
# ...

hashcat -m 11300 hash.txt -a 3 -1 'ghijklmnopqrstuvwxyz0123456789!?@' '?1?a?a?a?a'
```

hashcat does not natively share state with `btc-legacy-brute`, so the
trick is to **partition by prefix**: each tool handles a different
prefix range, so there's no overlap.

---

## 8. Future: native OpenCL kernel for `btc-legacy-brute`

We are working on adding an **OpenCL kernel** directly to
`btc-legacy-brute` so that you don't need hashcat at all. Benefits:

- Same CLI as `btc-legacy-brute` (consistent UX)
- Same state file format (resume across CPU/GPU runs)
- Works on Intel/AMD/NVIDIA via OpenCL (no CUDA lock-in)
- Still no telemetry / no cloud / no upload

Status: **planned for v1.1**. The kernel will implement:

- SHA-512 (64-bit integer ops, 80 rounds per block)
- EVP_BytesToKey outer loop (25000 iterations per candidate)
- AES-256-CBC decrypt (single block, since master key is 32 bytes)
- PKCS7 padding check

The kernel will be ~500 lines of OpenCL C. Host code will dispatch
work to the GPU and check results from CPU. Estimated speedup on
Iris Xe: **3-5×** over CPU. On NVIDIA RTX 3080: **200-400×**.

Until then, the `hashdump → hashcat` path is the recommended GPU
workflow.

---

## 9. Quick reference

```bash
# 1. Extract hash from wallet
btc-legacy hashdump wallet.dat > hash.txt

# 2. Check hashcat sees your GPU
hashcat -I

# 3. Benchmark hashcat on this hash type
hashcat -m 11300 --benchmark

# 4. Run the attack
hashcat -m 11300 hash.txt -a 3 '?d?d?d?d'    # mask
hashcat -m 11300 hash.txt wordlist.txt        # dictionary
hashcat -m 11300 hash.txt -a 3 'Bitcoin?d?d?d?d'   # prefix + digits

# 5. Show the recovered passphrase
hashcat -m 11300 hash.txt --show
```

For full hashcat usage, see:
- `hashcat --help`
- https://hashcat.net/wiki/
- https://github.com/hashcat/hashcat

---

## 10. See also

- `PATTERNS.md` — full mask + dictionary + brute pattern reference
- `SAMPLES.md` — actual command output for each example
- `FORMAT.md` — wallet.dat format (mkey / ckey internals)
- `SECURITY.md` — security model
