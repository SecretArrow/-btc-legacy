// src/brute/brute.cpp
//
// Multi-threaded brute-force passphrase recovery for legacy Bitcoin
// wallet.dat files. Reuses btc-legacy's wallet::verify_passphrase
// (CCrypter-equivalent: EVP_BytesToKey SHA-512 + AES-256-CBC) so the
// recovery is verified against the wallet's actual encryption
// metadata — no false positives, no false negatives.
//
// Iteration order
// ---------------
// The full search space is the concatenation, for L = min_len .. max_len,
// of all charset^L candidates of length L in lexicographic order. We
// enumerate this space by a single global index `i ∈ [0, total)` and
// convert each index to a candidate string. This makes the search
// resumable: saving `next_index` is enough to continue.
//
// State file
// ----------
// Plain-text, one key=value per line, saved every `state_interval_sec`
// seconds by the main thread and on every clean exit (Ctrl-C / SIGTERM).
// Loaded on `--resume`.
//
// Tried-passwords log
// -------------------
// Append-only text file with one candidate per line. Useful when the
// user changes charset/length between runs and wants to skip
// previously-tried candidates regardless of index scheme. Read on
// start (if --resume and file exists) into an in-memory set; updated
// by the worker threads (no locking needed since append-only + POSIX
// O_APPEND is atomic for short writes).
//
// Threading
// ---------
// Each worker thread atomically grabs the next index from a shared
// atomic<uint64_t>, generates the candidate string, calls
// verify_passphrase, and writes the candidate to the tried log. If
// a thread finds the passphrase, it sets a global atomic<bool> found
// flag and the others stop within their next iteration.
//
#include "btclegacy/brute/brute.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/time_util.h"
#include "btclegacy/util/strings.h"
#include "btclegacy/util/sha256.h"

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cmath>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>

namespace btclegacy::brute {

// ---------------------------------------------------------------------------
// Character-set presets
// ---------------------------------------------------------------------------

const CharsetPreset kCharsetPresets[] = {
    {"digits", "0123456789"},
    {"lower",  "abcdefghijklmnopqrstuvwxyz"},
    {"upper",  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"alpha",  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"alnum",  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
    {"all",    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
               "!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\ "},
    {"hex",    "0123456789abcdef"},
    {"hexu",   "0123456789ABCDEF"},
};

std::string resolve_charset(const std::string& mode_or_custom) {
    for (const auto& p : kCharsetPresets) {
        if (mode_or_custom == p.name) return p.chars;
    }
    // Not a preset name — assume it's a literal custom charset.
    return mode_or_custom;
}

// ---------------------------------------------------------------------------
// Mode dispatch
// ---------------------------------------------------------------------------

enum class Mode { Brute, Wordlist, Mask };

static Mode detect_mode(const Config& c) {
    if (!c.mask.empty()) return Mode::Mask;
    if (!c.wordlist_path.empty()) return Mode::Wordlist;
    return Mode::Brute;
}

// ---------------------------------------------------------------------------
// Mask parsing
// ---------------------------------------------------------------------------

static const char* kMaskDigits  = "0123456789";
static const char* kMaskLower   = "abcdefghijklmnopqrstuvwxyz";
static const char* kMaskUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char* kMaskSymbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\ ";
static const char* kMaskAlnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const char* kMaskHexL    = "0123456789abcdef";
static const char* kMaskHexU    = "0123456789ABCDEF";

std::vector<MaskSlot> parse_mask(const Config& c, std::string& err) {
    std::vector<MaskSlot> slots;
    std::string literal_buf;
    auto flush_literal = [&]() {
        if (!literal_buf.empty()) {
            MaskSlot s; s.is_placeholder = false; s.literal = literal_buf;
            slots.push_back(std::move(s));
            literal_buf.clear();
        }
    };
    const std::string& m = c.mask;
    for (size_t i = 0; i < m.size(); ++i) {
        char ch = m[i];
        if (ch != '?') {
            literal_buf.push_back(ch);
            continue;
        }
        // Need at least one more char after '?'
        if (i + 1 >= m.size()) {
            err = std::string("mask ends with trailing '?' - use ") +
                  "'??" "?' for a literal '?'";
            // (string-literal concatenation above avoids the C++ ??' trigraph)
            return {};
        }
        char placeholder = m[++i];
        if (placeholder == '?') {
            literal_buf.push_back('?');
            continue;
        }
        const char* cs = nullptr;
        std::string custom_str;
        switch (placeholder) {
            case 'd': cs = kMaskDigits; break;
            case 'l': cs = kMaskLower; break;
            case 'u': cs = kMaskUpper; break;
            case 's': cs = kMaskSymbols; break;
            case 'a': cs = kMaskAlnum; break;
            case 'h': cs = kMaskHexL; break;
            case 'H': cs = kMaskHexU; break;
            case '1':
                if (c.custom1.empty()) {
                    err = "mask uses ?1 but --custom1 is empty";
                    return {};
                }
                custom_str = c.custom1;
                cs = custom_str.c_str();
                break;
            case '2':
                if (c.custom2.empty()) {
                    err = "mask uses ?2 but --custom2 is empty";
                    return {};
                }
                custom_str = c.custom2;
                cs = custom_str.c_str();
                break;
            default:
                err = std::string("unknown mask placeholder '?") + placeholder + "'";
                return {};
        }
        flush_literal();
        MaskSlot s;
        s.is_placeholder = true;
        s.charset = cs;
        slots.push_back(std::move(s));
    }
    flush_literal();
    return slots;
}

// ---------------------------------------------------------------------------
// Search space math
// ---------------------------------------------------------------------------

static uint64_t pow_charset(size_t base, size_t exp) {
    uint64_t r = 1;
    for (size_t i = 0; i < exp; ++i) {
        // Overflow check — anything beyond uint64 is hopeless anyway
        if (r > (UINT64_MAX / base)) return UINT64_MAX;
        r *= base;
    }
    return r;
}

uint64_t search_space_size(const Config& c) {
    Mode mode = detect_mode(c);
    if (mode == Mode::Wordlist) {
        // Counted lazily in run_brute after loading; here we return 0
        // (the caller should not call this for wordlist mode pre-load).
        return 0;
    }
    if (mode == Mode::Mask) {
        std::string err;
        auto slots = parse_mask(c, err);
        if (!err.empty()) return 0;
        uint64_t total = 1;
        for (auto& s : slots) {
            if (!s.is_placeholder) continue;
            if (s.charset.empty()) return 0;
            if (total > UINT64_MAX / s.charset.size()) return UINT64_MAX;
            total *= s.charset.size();
        }
        return total;
    }
    // Brute force
    uint64_t total = 0;
    const size_t base = c.charset.size();
    if (base == 0) return 0;
    for (size_t L = c.min_len; L <= c.max_len; ++L) {
        uint64_t n = pow_charset(base, L);
        if (n == UINT64_MAX) return UINT64_MAX;
        total += n;
        if (total > UINT64_MAX - n) return UINT64_MAX;
    }
    return total;
}

std::string index_to_candidate(const Config& c, uint64_t i) {
    Mode mode = detect_mode(c);
    if (mode == Mode::Mask) {
        std::string err;
        auto slots = parse_mask(c, err);
        if (!err.empty()) return std::string{};
        // Convert i to per-placeholder digit positions (mixed-radix,
        // right-to-left)
        std::vector<size_t> positions;
        positions.reserve(slots.size());
        for (size_t k = 0; k < slots.size(); ++k) positions.push_back(0);
        // The rightmost placeholder varies fastest.
        // Walk slots right-to-left, allocating i into positions.
        for (size_t k_idx = slots.size(); k_idx-- > 0; ) {
            const MaskSlot& s = slots[k_idx];
            if (!s.is_placeholder) continue;
            size_t base = s.charset.size();
            if (base == 0) return std::string{};
            positions[k_idx] = size_t(i % base);
            i /= base;
        }
        // Build the candidate string from slots left-to-right
        std::string out;
        out.reserve(32);
        for (size_t k = 0; k < slots.size(); ++k) {
            const MaskSlot& s = slots[k];
            if (s.is_placeholder) out.push_back(s.charset[positions[k]]);
            else                  out.append(s.literal);
        }
        return c.prefix + out + c.suffix;
    }
    if (mode == Mode::Wordlist) {
        // Wordlist mode uses index = line number; the actual lookup
        // happens in run_brute where the wordlist is loaded. Returning
        // empty here for wordlist mode is fine — the worker bypasses
        // this function in wordlist mode.
        return std::string{};
    }
    // Brute force
    const size_t base = c.charset.size();
    if (base == 0) return std::string{};
    size_t L = c.min_len;
    while (L <= c.max_len) {
        uint64_t cnt = pow_charset(base, L);
        if (i < cnt) break;
        i -= cnt;
        ++L;
    }
    if (L > c.max_len) return std::string{};
    std::string s;
    s.reserve(L);
    for (size_t k = 0; k < L; ++k) {
        s.push_back(c.charset[size_t(i % base)]);
        i /= base;
    }
    std::reverse(s.begin(), s.end());
    return c.prefix + s + c.suffix;
}

// ---------------------------------------------------------------------------
// State file I/O
// ---------------------------------------------------------------------------

struct State {
    std::string wallet_path;
    std::string mode;          // "brute" | "wordlist" | "mask"
    std::string charset;
    size_t      min_len = 1;
    size_t      max_len = 1;
    std::string prefix;
    std::string suffix;
    std::string wordlist_path;
    std::string wordlist_sha256;
    std::string mask;
    std::string custom1;
    std::string custom2;
    uint64_t    next_index = 0;
    uint64_t    tried_count = 0;
    uint64_t    total_space = 0;
    uint64_t    start_unix = 0;
    uint64_t    last_save_unix = 0;
    bool        found = false;
    std::string found_passphrase;
};

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b - a);
}

static bool load_state(const std::string& path, State& out, std::string& err) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = trim(line.substr(eq+1));
        if      (k == "wallet")           out.wallet_path = v;
        else if (k == "mode")              out.mode = v;
        else if (k == "charset")           out.charset = v;
        else if (k == "min_len")           out.min_len = std::stoul(v);
        else if (k == "max_len")           out.max_len = std::stoul(v);
        else if (k == "prefix")            out.prefix = v;
        else if (k == "suffix")            out.suffix = v;
        else if (k == "wordlist_path")     out.wordlist_path = v;
        else if (k == "wordlist_sha256")   out.wordlist_sha256 = v;
        else if (k == "mask")              out.mask = v;
        else if (k == "custom1")           out.custom1 = v;
        else if (k == "custom2")           out.custom2 = v;
        else if (k == "next_index")        out.next_index = std::stoull(v);
        else if (k == "tried_count")       out.tried_count = std::stoull(v);
        else if (k == "total_space")       out.total_space = std::stoull(v);
        else if (k == "start_unix")        out.start_unix = std::stoull(v);
        else if (k == "last_save_unix")    out.last_save_unix = std::stoull(v);
        else if (k == "found")             out.found = (v == "1" || v == "true");
        else if (k == "found_passphrase")  out.found_passphrase = v;
    }
    return true;
}

static bool save_state(const std::string& path, const State& s, std::string& err) {
    std::string tmp = path + ".tmp";
    std::ofstream f(tmp, std::ios::trunc);
    if (!f) { err = "cannot write state file: " + tmp; return false; }
    f << "# btc-legacy-brute state v1\n";
    f << "wallet=" << s.wallet_path << "\n";
    f << "mode=" << s.mode << "\n";
    f << "charset=" << s.charset << "\n";
    f << "min_len=" << s.min_len << "\n";
    f << "max_len=" << s.max_len << "\n";
    f << "prefix=" << s.prefix << "\n";
    f << "suffix=" << s.suffix << "\n";
    f << "wordlist_path=" << s.wordlist_path << "\n";
    f << "wordlist_sha256=" << s.wordlist_sha256 << "\n";
    f << "mask=" << s.mask << "\n";
    f << "custom1=" << s.custom1 << "\n";
    f << "custom2=" << s.custom2 << "\n";
    f << "next_index=" << s.next_index << "\n";
    f << "tried_count=" << s.tried_count << "\n";
    f << "total_space=" << s.total_space << "\n";
    f << "start_unix=" << s.start_unix << "\n";
    f << "last_save_unix=" << s.last_save_unix << "\n";
    f << "found=" << (s.found ? "1" : "0") << "\n";
    if (s.found) f << "found_passphrase=" << s.found_passphrase << "\n";
    f.close();
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "rename failed: " + tmp + " -> " + path;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tried-passwords log
// ---------------------------------------------------------------------------

static bool load_tried_set(const std::string& path,
                            std::unordered_set<std::string>& out) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) out.insert(line);
    }
    return true;
}

static bool append_tried(const std::string& path, const std::string& candidate) {
    // O_APPEND guarantees atomic short writes on POSIX (≤ PIPE_BUF)
    std::ofstream f(path, std::ios::out | std::ios::app);
    if (!f) return false;
    f << candidate << "\n";
    return f.good();
}

// ---------------------------------------------------------------------------
// Result writer
// ---------------------------------------------------------------------------

static bool write_result(const std::string& path,
                          const std::string& wallet_path,
                          const std::string& passphrase,
                          uint64_t attempts,
                          double elapsed) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << "FOUND\n";
    f << "wallet=" << wallet_path << "\n";
    f << "passphrase=" << passphrase << "\n";
    f << "found_at=" << util::format_datetime_iso(util::now_unix_seconds()) << "\n";
    f << "attempts=" << attempts << "\n";
    f << "elapsed_seconds=" << std::fixed << std::setprecision(2) << elapsed << "\n";
    return f.good();
}

// ---------------------------------------------------------------------------
// Progress display
// ---------------------------------------------------------------------------

static std::string format_eta(double seconds) {
    if (seconds < 0 || !std::isfinite(seconds)) return "?";
    if (seconds > 1e9) return "inf";
    uint64_t s = uint64_t(seconds);
    uint64_t d = s / 86400; s %= 86400;
    uint64_t h = s / 3600;  s %= 3600;
    uint64_t m = s / 60;    s %= 60;
    std::ostringstream os;
    if (d > 0) os << d << "d ";
    if (h > 0 || d > 0) os << h << "h ";
    if (m > 0 || h > 0 || d > 0) os << m << "m ";
    os << s << "s";
    return os.str();
}

static std::string format_thousands(uint64_t n) {
    std::ostringstream os;
    os.imbue(std::locale("C"));
    os << n;
    std::string s = os.str();
    // Insert thousands separators
    size_t len = s.size();
    if (len <= 3) return s;
    std::string out;
    size_t cnt = 0;
    for (auto it = s.rbegin(); it != s.rend(); ++it) {
        if (cnt && cnt % 3 == 0) out.push_back(',');
        out.push_back(*it);
        ++cnt;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

static std::string format_clock() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    // gmtime_s args are reversed vs. gmtime_r: (output, input) on MSVC/MinGW.
    gmtime_s(&tm, &t);
#else
    ::gmtime_r(&t, &tm);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

// ---------------------------------------------------------------------------
// SIGINT handler — set a flag the main loop checks so we can save state
// ---------------------------------------------------------------------------

namespace {
std::atomic<bool> g_interrupted{false};
void sigint_handler(int) { g_interrupted.store(true, std::memory_order_relaxed); }
} // namespace

// ---------------------------------------------------------------------------
// Main run_brute
// ---------------------------------------------------------------------------

Result run_brute(const Config& c) {
    Result r;
    Mode mode = detect_mode(c);

    // Parse the wallet once (shared across all worker threads — read-only).
    wallet::ParsedWallet pw;
    bool is_bdb = false;
    std::string perr;
    if (!wallet::parse_wallet(c.wallet_path, pw, perr, nullptr, &is_bdb)) {
        r.errors.push_back("wallet parse failed: " + perr);
        return r;
    }
    if (!pw.encrypted) {
        r.errors.push_back("wallet is not encrypted — nothing to brute-force");
        return r;
    }
    if (pw.master_keys.empty()) {
        r.errors.push_back("wallet is encrypted but has no mkey record");
        return r;
    }

    // Default file paths
    std::string state_file = c.state_file.empty()
        ? c.wallet_path + ".brute-state" : c.state_file;
    std::string tried_file = c.tried_file.empty()
        ? c.wallet_path + ".tried" : c.tried_file;
    std::string result_file = c.result_file.empty()
        ? "result.txt" : c.result_file;

    // Mode-specific setup: load wordlist, parse mask, compute total_space
    std::vector<std::string> wordlist;
    std::string wordlist_sha256;
    std::vector<MaskSlot> mask_slots;
    if (mode == Mode::Wordlist) {
        // Load wordlist
        std::ifstream wf(c.wordlist_path);
        if (!wf) {
            r.errors.push_back("cannot open wordlist: " + c.wordlist_path);
            return r;
        }
        std::string line;
        while (std::getline(wf, line)) {
            // Strip a single trailing CR if present (CRLF line endings)
            if (!line.empty() && line.back() == '\r') line.pop_back();
            wordlist.push_back(line);
        }
        // Compute SHA-256 of file for state validation
        wordlist_sha256 = util::sha256_hex_file(c.wordlist_path);
        r.total_space = wordlist.size();
    } else if (mode == Mode::Mask) {
        std::string merr;
        mask_slots = parse_mask(c, merr);
        if (!merr.empty()) {
            r.errors.push_back("mask parse error: " + merr);
            return r;
        }
        uint64_t total = 1;
        for (auto& s : mask_slots) {
            if (!s.is_placeholder) continue;
            if (s.charset.empty()) { r.errors.push_back("empty charset in mask slot"); return r; }
            if (total > UINT64_MAX / s.charset.size()) { r.total_space = UINT64_MAX; total = UINT64_MAX; break; }
            total *= s.charset.size();
        }
        r.total_space = total;
    } else {
        r.total_space = search_space_size(c);
    }

    // Initialize state struct
    State st{};
    st.wallet_path = c.wallet_path;
    st.mode = (mode == Mode::Mask)    ? "mask"     :
              (mode == Mode::Wordlist) ? "wordlist" : "brute";
    st.charset = c.charset;
    st.min_len = c.min_len;
    st.max_len = c.max_len;
    st.prefix = c.prefix;
    st.suffix = c.suffix;
    st.wordlist_path = c.wordlist_path;
    st.wordlist_sha256 = wordlist_sha256;
    st.mask = c.mask;
    st.custom1 = c.custom1;
    st.custom2 = c.custom2;
    st.total_space = r.total_space;
    st.start_unix = util::now_unix_seconds();

    if (c.resume && !c.no_resume) {
        std::string serr;
        State loaded{};
        if (load_state(state_file, loaded, serr)) {
            // If mode differs, we don't refuse — we just skip the
            // state load (since the index space differs) but still
            // use the tried-set (loaded below) for cross-mode
            // deduplication. This makes multi-pass strategies work
            // across mode changes.
            bool mode_matches = (loaded.mode == st.mode);
            bool cfg_match = true;
            if (mode_matches) {
                if (mode == Mode::Brute) {
                    cfg_match = (loaded.charset == c.charset &&
                                 loaded.min_len == c.min_len &&
                                 loaded.max_len == c.max_len);
                } else if (mode == Mode::Wordlist) {
                    cfg_match = (loaded.wordlist_sha256 == wordlist_sha256);
                } else if (mode == Mode::Mask) {
                    cfg_match = (loaded.mask == c.mask &&
                                 loaded.custom1 == c.custom1 &&
                                 loaded.custom2 == c.custom2);
                }
                cfg_match = cfg_match &&
                    (loaded.prefix == c.prefix && loaded.suffix == c.suffix);
            } else {
                cfg_match = false;
            }
            if (cfg_match) {
                if (loaded.found) {
                    r.found = true;
                    r.passphrase = loaded.found_passphrase;
                    r.attempts = loaded.tried_count;
                    return r;
                }
                st.next_index = loaded.next_index;
                st.tried_count = loaded.tried_count;
                st.start_unix = loaded.start_unix;
            }
            // If mode differs, fall through with st.next_index = 0 (fresh).
            // The tried-set is still loaded below, so previously-tried
            // candidates will be skipped.
        }
    }

    // Load tried set (for cross-run deduplication) — always loaded
    // (unless --no-resume) so that multi-pass strategies across different
    // modes can still skip previously-tried candidates.
    std::unordered_set<std::string> tried_set;
    if (!c.no_resume) {
        load_tried_set(tried_file, tried_set);
    }

    // Shared atomic state
    const size_t n_threads = c.threads > 0 ? c.threads : 1;
    std::atomic<uint64_t> next_index(st.next_index);
    std::atomic<uint64_t> attempts_count(st.tried_count);
    std::atomic<bool> found(false);
    std::atomic<uint64_t> found_index(UINT64_MAX);
    std::string found_passphrase;     // protected by found_mutex
    std::mutex found_mutex;
    std::atomic<bool> stop(false);
    std::atomic<size_t> active_threads(n_threads);

    // Install SIGINT handler
    std::signal(SIGINT, sigint_handler);
    std::signal(SIGTERM, sigint_handler);

    auto t_start = std::chrono::steady_clock::now();
    auto t_last_progress = t_start;
    auto t_last_state = t_start;

    if (!c.quiet && !c.json) {
        std::cerr << "btc-legacy-brute — brute-force passphrase recovery\n";
        std::cerr << "  wallet        : " << c.wallet_path << "\n";
        std::cerr << "  mode          : " << st.mode << "\n";
        if (mode == Mode::Brute) {
            std::cerr << "  charset       : " << c.charset << " (" << c.charset.size() << " chars)\n";
            std::cerr << "  length range  : " << c.min_len << " .. " << c.max_len << "\n";
        } else if (mode == Mode::Wordlist) {
            std::cerr << "  wordlist      : " << c.wordlist_path << " ("
                      << format_thousands(wordlist.size()) << " candidates)\n";
        } else if (mode == Mode::Mask) {
            std::cerr << "  mask          : " << c.mask << "\n";
            if (!c.custom1.empty()) std::cerr << "  custom1       : " << c.custom1 << "\n";
            if (!c.custom2.empty()) std::cerr << "  custom2       : " << c.custom2 << "\n";
        }
        std::cerr << "  prefix/suffix : '" << c.prefix << "' / '" << c.suffix << "'\n";
        std::cerr << "  total space   : " << format_thousands(r.total_space) << "\n";
        std::cerr << "  threads       : " << n_threads << "\n";
        std::cerr << "  resume        : " << (c.resume ? "yes" : "no") << "\n";
        std::cerr << "  starting at   : index " << format_thousands(st.next_index) << "\n";
        std::cerr << "  state file    : " << state_file << "\n";
        std::cerr << "  tried file    : " << tried_file << "\n";
        std::cerr << "  result file   : " << result_file << "\n";
        std::cerr << "Press Ctrl-C to stop and save state.\n\n";
    }

    // Helper to convert an index to a candidate string in the active mode.
    auto make_candidate = [&](uint64_t idx) -> std::string {
        if (mode == Mode::Wordlist) {
            if (idx >= wordlist.size()) return std::string{};
            return c.prefix + wordlist[size_t(idx)] + c.suffix;
        }
        if (mode == Mode::Mask) {
            if (mask_slots.empty()) return std::string{};
            std::vector<size_t> positions(mask_slots.size(), 0);
            uint64_t i = idx;
            for (size_t k_idx = mask_slots.size(); k_idx-- > 0; ) {
                const MaskSlot& s = mask_slots[k_idx];
                if (!s.is_placeholder) continue;
                size_t base = s.charset.size();
                if (base == 0) return std::string{};
                positions[k_idx] = size_t(i % base);
                i /= base;
            }
            std::string out;
            out.reserve(32);
            for (size_t k = 0; k < mask_slots.size(); ++k) {
                const MaskSlot& s = mask_slots[k];
                if (s.is_placeholder) out.push_back(s.charset[positions[k]]);
                else                  out.append(s.literal);
            }
            return c.prefix + out + c.suffix;
        }
        // Brute
        return index_to_candidate(c, idx);
    };

    auto worker = [&]() {
        std::vector<std::string> local_tried_batch;
        local_tried_batch.reserve(64);
        while (!stop.load(std::memory_order_relaxed)) {
            if (g_interrupted.load(std::memory_order_relaxed)) {
                stop.store(true, std::memory_order_relaxed);
                goto done;
            }
            uint64_t idx = next_index.fetch_add(1, std::memory_order_relaxed);
            if (idx >= r.total_space) goto done;
            if (c.max_attempts > 0 &&
                attempts_count.load(std::memory_order_relaxed) >= c.max_attempts) {
                stop.store(true, std::memory_order_relaxed);
                goto done;
            }
            std::string candidate = make_candidate(idx);
            if (candidate.empty()) goto done;

            bool skip = false;
            if (!tried_set.empty()) {
                if (tried_set.count(candidate) > 0) skip = true;
            }
            if (!skip) {
                platform::SecureBuffer master;
                bool ok = wallet::verify_passphrase(pw, candidate, master, perr);
                if (ok) {
                    {
                        std::lock_guard<std::mutex> g(found_mutex);
                        found_passphrase = candidate;
                    }
                    found_index.store(idx, std::memory_order_relaxed);
                    found.store(true, std::memory_order_relaxed);
                    stop.store(true, std::memory_order_relaxed);
                    goto done;
                }
            }
            attempts_count.fetch_add(1, std::memory_order_relaxed);
            local_tried_batch.push_back(candidate);
            if (local_tried_batch.size() >= 64) {
                std::lock_guard<std::mutex> g(found_mutex);
                for (auto& s : local_tried_batch) {
                    append_tried(tried_file, s);
                }
                local_tried_batch.clear();
            }
        }
        done:
        if (!local_tried_batch.empty()) {
            std::lock_guard<std::mutex> g(found_mutex);
            for (auto& s : local_tried_batch) {
                append_tried(tried_file, s);
            }
        }
        active_threads.fetch_sub(1, std::memory_order_relaxed);
    };

    std::vector<std::thread> threads;
    for (size_t i = 0; i < n_threads; ++i) {
        threads.emplace_back(worker);
    }

    // Progress + state-saving monitor loop runs in the calling thread.
    // Exits when active_threads hits 0 OR when found becomes true AND
    // all threads have exited.
    while (true) {
        if (active_threads.load(std::memory_order_relaxed) == 0) break;
        if (found.load(std::memory_order_relaxed)) {
            // Threads will see the stop flag and exit within one iteration;
            // sleep briefly so we don't busy-loop.
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (active_threads.load(std::memory_order_relaxed) == 0) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto now = std::chrono::steady_clock::now();
        if (!c.quiet && !c.json) {
            double since_progress = std::chrono::duration<double>(
                now - t_last_progress).count();
            if (since_progress >= c.progress_interval_sec) {
                t_last_progress = now;
                uint64_t tried = attempts_count.load(std::memory_order_relaxed);
                uint64_t next = next_index.load(std::memory_order_relaxed);
                double elapsed = std::chrono::duration<double>(
                    now - t_start).count();
                double rate = (elapsed > 0) ? double(tried) / elapsed : 0;
                double pct = r.total_space > 0
                    ? 100.0 * double(tried) / double(r.total_space) : 0;
                double remaining = (rate > 0)
                    ? double(r.total_space - tried) / rate : -1;
                std::string cur = make_candidate(next < r.total_space ? next : r.total_space - 1);
                std::cerr << "\r[" << format_clock() << "] "
                          << "tried=" << std::setw(12) << format_thousands(tried)
                          << " / " << std::setw(12) << format_thousands(r.total_space)
                          << " (" << std::fixed << std::setprecision(3) << pct << "%)  "
                          << "speed=" << std::fixed << std::setprecision(0) << rate << "/s  "
                          << "eta=" << format_eta(remaining) << "  "
                          << "cur=\"" << util::redact(cur, 8) << "\"          "
                          << std::flush;
            }
        }
        double since_state = std::chrono::duration<double>(
            now - t_last_state).count();
        if (since_state >= c.state_interval_sec) {
            t_last_state = now;
            State snapshot = st;
            snapshot.next_index = next_index.load(std::memory_order_relaxed);
            snapshot.tried_count = attempts_count.load(std::memory_order_relaxed);
            snapshot.last_save_unix = util::now_unix_seconds();
            std::string serr;
            if (!save_state(state_file, snapshot, serr) && !c.quiet) {
                std::cerr << "\nwarning: state save failed: " << serr << "\n";
            }
        }
    }
    for (auto& t : threads) if (t.joinable()) t.join();

    auto t_end = std::chrono::steady_clock::now();
    r.elapsed_seconds = std::chrono::duration<double>(t_end - t_start).count();
    r.attempts = attempts_count.load(std::memory_order_relaxed);
    r.found = found.load(std::memory_order_relaxed);
    if (r.found) {
        std::lock_guard<std::mutex> g(found_mutex);
        r.passphrase = found_passphrase;
        // Write to result file
        write_result(result_file, c.wallet_path, r.passphrase,
                      r.attempts, r.elapsed_seconds);
        if (!c.json) {
            std::cerr << "\n\n*** FOUND ***\n";
            std::cerr << "wallet     : " << c.wallet_path << "\n";
            std::cerr << "passphrase : " << r.passphrase << "\n";
            std::cerr << "attempts   : " << format_thousands(r.attempts) << "\n";
            std::cerr << "elapsed    : " << format_eta(r.elapsed_seconds) << "\n";
            std::cerr << "written to : " << result_file << "\n";
        } else {
            std::cout << "{\"found\":true,\"wallet\":\""
                      << c.wallet_path << "\",\"passphrase\":\""
                      << r.passphrase << "\",\"attempts\":"
                      << r.attempts << ",\"elapsed_seconds\":"
                      << r.elapsed_seconds << "}\n";
        }
    } else {
        if (!c.json) {
            std::cerr << "\n\nNot found in the configured search space.\n";
            std::cerr << "Tried " << format_thousands(r.attempts) << " candidates in "
                      << format_eta(r.elapsed_seconds) << ".\n";
            std::cerr << "Next index would be "
                      << format_thousands(next_index.load(std::memory_order_relaxed))
                      << " — resume with --resume.\n";
        } else {
            std::cout << "{\"found\":false,\"wallet\":\""
                      << c.wallet_path << "\",\"attempts\":"
                      << r.attempts << ",\"elapsed_seconds\":"
                      << r.elapsed_seconds << ",\"next_index\":"
                      << next_index.load(std::memory_order_relaxed) << "}\n";
        }
    }

    // Final state save
    {
        State snapshot = st;
        snapshot.next_index = next_index.load(std::memory_order_relaxed);
        snapshot.tried_count = attempts_count.load(std::memory_order_relaxed);
        snapshot.last_save_unix = util::now_unix_seconds();
        snapshot.found = r.found;
        snapshot.found_passphrase = r.found ? r.passphrase : std::string{};
        std::string serr;
        save_state(state_file, snapshot, serr);
    }
    return r;
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

void print_help(std::ostream& out) {
    out <<
        "btc-legacy-brute — offline brute-force passphrase recovery for legacy Bitcoin wallet.dat\n"
        "\n"
        "USAGE\n"
        "  btc-legacy-brute <wallet.dat> [options]\n"
        "\n"
        "DESCRIPTION\n"
        "  Multi-threaded offline passphrase search for legacy Bitcoin Core\n"
        "  wallet.dat files (2009–2015). Reuses btc-legacy's verified\n"
        "  CCrypter-compatible passphrase verifier — no false positives.\n"
        "\n"
        "  The tool only attacks wallets you already have file-system access\n"
        "  to; it has no network functionality.\n"
        "\n"
        "SEARCH MODES (mutually exclusive)\n"
        "\n"
        "  Mode 1 — Brute force (default):\n"
        "    Iterate every combination of a charset over a length range.\n"
        "    --mode MODE          digits|lower|upper|alpha|alnum|hex|hexu|all|custom\n"
        "    --charset STRING     Custom charset (overrides --mode)\n"
        "    --min-len N          Minimum length (default 1, inclusive)\n"
        "    --max-len N          Maximum length (required, inclusive)\n"
        "\n"
        "  Mode 2 — Dictionary attack:\n"
        "    Read candidates one-per-line from a file.\n"
        "    --wordlist PATH      Path to a UTF-8 wordlist file\n"
        "\n"
        "  Mode 3 — Mask attack:\n"
        "    Pattern-based search with placeholders.\n"
        "    --mask PATTERN       e.g. '?d?d?d?d' for 4-digit PIN,\n"
        "                         'pass?d?d?d' for prefix + 3 digits\n"
        "    --custom1 STRING     Charset for the ?1 placeholder\n"
        "    --custom2 STRING     Charset for the ?2 placeholder\n"
        "\n"
        "    Mask placeholders:\n"
        "      ?d  digit (0-9)              ?l  lowercase (a-z)\n"
        "      ?u  uppercase (A-Z)          ?s  symbol (!@#$%^&*()_+-=...)\n"
        "      ?a  alnum (a-zA-Z0-9)        ?h  hex lower (0-9a-f)\n"
        "      ?H  hex upper (0-9A-F)       ?1  custom-1 (--custom1)\n"
        "      ?2  custom-2 (--custom2)     ??  literal '?'\n"
        "      Any other char is treated as a literal.\n"
        "\n"
        "CHARACTER SET MODES (--mode, brute force only)\n"
        "  digits     0-9                                  (10 chars)\n"
        "  lower      a-z                                  (26 chars)\n"
        "  upper      A-Z                                  (26 chars)\n"
        "  alpha      a-zA-Z                               (52 chars)\n"
        "  alnum      a-zA-Z0-9                            (62 chars)\n"
        "  hex        0-9a-f                                (16 chars)\n"
        "  hexu       0-9A-F                                (16 chars)\n"
        "  all        alnum + common symbols              (95 chars)\n"
        "  custom     use --charset STRING instead\n"
        "\n"
        "PREFIX / SUFFIX (apply in all modes)\n"
        "  --prefix STR    Fixed prefix prepended to every candidate\n"
        "  --suffix STR    Fixed suffix appended to every candidate\n"
        "  (Useful when you remember part of the passphrase, e.g.\n"
        "   --prefix 'MyWallet' --suffix '2020')\n"
        "\n"
        "RESUME / STATE\n"
        "  --resume            Load state from <wallet>.brute-state and continue\n"
        "                      from where the previous run left off.\n"
        "  --no-resume         Ignore any existing state file (start fresh).\n"
        "  --state-file PATH   Override the state file location.\n"
        "  --state-interval N  Save state every N seconds (default 5).\n"
        "\n"
        "TRIED-PASSWORDS LOG\n"
        "  Every candidate is appended to <wallet>.tried (one per line).\n"
        "  On --resume, candidates already in this log are skipped.\n"
        "  --tried-file PATH   Override the tried-log location.\n"
        "\n"
        "OUTPUT\n"
        "  --result-file PATH   Where to write the found passphrase.\n"
        "                       Default: ./result.txt\n"
        "  --json                Emit JSON progress + result to stdout.\n"
        "  --quiet              Suppress progress display.\n"
        "  --progress-interval N  Seconds between progress updates (default 1).\n"
        "\n"
        "EXECUTION\n"
        "  --threads N          Number of worker threads (default: hardware concurrency).\n"
        "  --max-attempts N     Bail out after N total attempts (0 = unlimited).\n"
        "\n"
        "EXAMPLES\n"
        "  # 4-digit PIN (brute force)\n"
        "  btc-legacy-brute wallet.dat --mode digits --min-len 4 --max-len 4\n"
        "\n"
        "  # 4-digit PIN (mask attack — same result, more explicit)\n"
        "  btc-legacy-brute wallet.dat --mask '?d?d?d?d'\n"
        "\n"
        "  # Prefix 'pass' + 3 lowercase letters (mask attack)\n"
        "  btc-legacy-brute wallet.dat --mask 'pass?l?l?l'\n"
        "\n"
        "  # Alphanumeric, 1–6 chars, 8 threads (brute force)\n"
        "  btc-legacy-brute wallet.dat --mode alnum --min-len 1 --max-len 6 \\\n"
        "      --threads 8\n"
        "\n"
        "  # Dictionary attack with rockyou.txt\n"
        "  btc-legacy-brute wallet.dat --wordlist rockyou.txt --threads 8\n"
        "\n"
        "  # Custom mask: 'wallet-' + 2 digits + 1 custom-charset char\n"
        "  btc-legacy-brute wallet.dat --mask 'wallet-?d?d?1' \\\n"
        "      --custom1 '!@#$'\n"
        "\n"
        "  # Resume a previous run\n"
        "  btc-legacy-brute wallet.dat --resume\n"
        "\n"
        "  # Everything, 1–5 chars, custom charset (brute force)\n"
        "  btc-legacy-brute wallet.dat --charset 'abc123!@#' --min-len 1 --max-len 5\n"
        "\n"
        "EXIT CODES\n"
        "  0   Passphrase found (also written to --result-file)\n"
        "  1   General error\n"
        "  2   Invalid argument\n"
        "  3   File not found\n"
        "  4   Unsupported wallet (not encrypted / no mkey)\n"
        "  5   Search space exhausted without finding the passphrase\n"
        "  6   Interrupted by user (state saved)\n"
        "\n"
        "SECURITY NOTES\n"
        "  * Operates entirely offline. No network I/O.\n"
        "  * State and tried files are written next to the wallet.\n"
        "  * The found passphrase is printed to stdout AND written to\n"
        "    result.txt. Handle both with care.\n"
        "  * Search speed is bounded by Bitcoin's KDF (EVP_BytesToKey\n"
        "    with SHA-512 and 25000 iterations per attempt). Expect\n"
        "    ~50–500 attempts/sec on a modern multi-core CPU.\n"
        "  * For long passphrases (>8 chars) brute-force is infeasible;\n"
        "    prefer dictionary attacks or partial-knowledge tools\n"
        "    such as BTCRecover instead.\n";
}

} // namespace btclegacy::brute
