// btclegacy/brute/brute.h
//
// Brute-force passphrase recovery for legacy Bitcoin wallet.dat files.
//
// Three search modes are supported:
//
//   1. Brute-force     (--mode / --charset + --min-len + --max-len)
//                       Iterate every combination of the charset over
//                       the length range in lexicographic order.
//
//   2. Dictionary      (--wordlist PATH)
//                       Read candidates one-per-line from a file.
//                       Prefix/suffix are still applied. Resume is
//                       index-based (next line number).
//
//   3. Mask attack     (--mask PATTERN)
//                       Pattern with placeholders:
//                         ?d  digit           (0-9)
//                         ?l  lowercase       (a-z)
//                         ?u  uppercase       (A-Z)
//                         ?s  symbol          (!@#$%^&*()_+-=...)
//                         ?a  alnum           (a-zA-Z0-9)
//                         ?h  hex lower       (0-9a-f)
//                         ?H  hex upper       (0-9A-F)
//                         ?1  custom-1        (--custom1 STR)
//                         ?2  custom-2        (--custom2 STR)
//                         ??  literal '?'
//                       Any other char is treated as a literal.
//                       Prefix/suffix apply on top.
//
// Security model:
//   * Operates entirely offline (no network).
//   * Only attacks wallets the operator already has file-system access
//     to (which is the threat-model assumption of btc-legacy itself:
//     anyone with read access to wallet.dat can mount an offline
//     passphrase search).
//   * State and tried-password logs are written next to the wallet,
//     NEVER uploaded.
//   * Found passphrases are written to result.txt and printed to
//     stdout, but are NEVER logged at info level before being found.
//
#pragma once
#include "btclegacy/wallet/wallet_parser.h"
#include "btclegacy/wallet/wallet_crypto.h"
#include "btclegacy/platform/secure_memory.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace btclegacy::brute {

// Character-set presets. The user can also supply a custom charset
// via --charset; the preset is then ignored.
struct CharsetPreset {
    const char* name;
    const char* chars;
};

extern const CharsetPreset kCharsetPresets[];

std::string resolve_charset(const std::string& mode_or_custom);

// All knobs for a brute-force run. The CLI parser populates this and
// hands it to run_brute().
struct Config {
    std::string wallet_path;

    // Mode 1: brute force
    std::string charset;     // resolved character set (e.g. "0123456789")
    size_t      min_len = 1; // inclusive
    size_t      max_len = 1; // inclusive

    // Mode 2: dictionary
    std::string wordlist_path;

    // Mode 3: mask
    std::string mask;
    std::string custom1;
    std::string custom2;

    // Common
    std::string prefix;     // fixed prefix for every candidate
    std::string suffix;     // fixed suffix

    // Execution
    size_t      threads = 1;
    bool        resume  = false;       // load state from disk
    bool        no_resume = false;     // ignore on-disk state
    int         progress_interval_sec = 1;
    int         state_interval_sec    = 5;
    uint64_t    max_attempts = 0;      // 0 = unlimited

    // Files
    std::string state_file;   // default: <wallet>.brute-state
    std::string tried_file;   // default: <wallet>.tried
    std::string result_file;  // default: result.txt
    std::string tried_set_file; // default: <wallet>.tried (same as tried_file)

    // Output
    bool        quiet = false;
    bool        json  = false;
};

// Result of a brute-force run. Even if not found, returns useful info.
struct Result {
    bool        found = false;
    std::string passphrase;
    uint64_t    attempts = 0;
    uint64_t    total_space = 0;
    double      elapsed_seconds = 0;
    std::string last_candidate; // for resumable display
    std::vector<std::string> errors;
};

// Compute the size of the search space for the given config.
uint64_t search_space_size(const Config& c);

// Convert a global index `i` (0-based) into the corresponding candidate
// string. Dispatches by mode (brute / dictionary / mask).
std::string index_to_candidate(const Config& c, uint64_t i);

// Parse a mask pattern into a list of "slots" — each slot is either
// a fixed string (literal) or a charset placeholder. Used both by
// search_space_size and index_to_candidate. Public so tests can call.
struct MaskSlot {
    bool is_placeholder = false;
    std::string literal;        // if !is_placeholder
    std::string charset;        // if is_placeholder
};
std::vector<MaskSlot> parse_mask(const Config& c, std::string& err);

// Run a brute-force search. Returns when either:
//   * The passphrase is found (Result.found = true)
//   * The entire search space is exhausted
//   * max_attempts is reached
//   * The user interrupts (Ctrl-C): the function returns the current
//     state, which can be resumed later.
Result run_brute(const Config& c);

// Print human-friendly help text to `out`.
void print_help(std::ostream& out);

} // namespace btclegacy::brute
