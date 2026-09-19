// src/brute/main.cpp
//
// Entry point for the btc-legacy-brute binary.
//
#include "btclegacy/brute/brute.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/file_util.h"
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

using namespace btclegacy;

namespace {

void usage_short() {
    std::cerr <<
        "btc-legacy-brute — offline brute-force passphrase recovery for legacy Bitcoin wallet.dat\n"
        "\n"
        "Usage: btc-legacy-brute <wallet.dat> [options]\n"
        "\n"
        "Search modes (mutually exclusive):\n"
        "  (default)            Brute force: --mode + --min-len/--max-len\n"
        "  --wordlist PATH      Dictionary attack: try every line in PATH\n"
        "  --mask PATTERN       Mask attack with placeholders ?d?l?u?s?a?h?H?1?2\n"
        "\n"
        "Brute-force options:\n"
        "  --mode MODE          digits|lower|upper|alpha|alnum|hex|hexu|all|custom\n"
        "  --charset STRING     Custom charset (overrides --mode)\n"
        "  --min-len N          Minimum length (default 1)\n"
        "  --max-len N          Maximum length (required in brute mode)\n"
        "\n"
        "Mask options:\n"
        "  --mask PATTERN       e.g. '?d?d?d?d' for 4-digit PIN, 'pass?d?d?d' for prefix+PIN\n"
        "  --custom1 STRING     Charset for ?1 placeholder\n"
        "  --custom2 STRING     Charset for ?2 placeholder\n"
        "\n"
        "Common options:\n"
        "  --prefix STR         Fixed prefix for every candidate\n"
        "  --suffix STR         Fixed suffix for every candidate\n"
        "  --threads N          Worker threads (default: hardware concurrency)\n"
        "  --resume             Resume from saved state\n"
        "  --no-resume          Ignore saved state, start fresh\n"
        "  --state-file PATH    Override state file location\n"
        "  --tried-file PATH    Override tried-log location\n"
        "  --result-file PATH   Where to write the found passphrase (default: result.txt)\n"
        "  --state-interval N   Save state every N seconds (default 5)\n"
        "  --progress-interval N  Progress update interval (default 1)\n"
        "  --max-attempts N     Stop after N attempts (0 = unlimited)\n"
        "  --json               JSON output (no progress display)\n"
        "  --quiet              Suppress progress\n"
        "  --help, -h           Show full help\n"
        "\n"
        "Run with --help for the full manual.\n";
}

// Parse an integer argument safely; returns false on parse error.
bool parse_size(const char* s, size_t& out) {
    if (!s) return false;
    char* endp = nullptr;
    unsigned long long v = std::strtoull(s, &endp, 10);
    if (!endp || *endp != '\0' || endp == s) return false;
    out = static_cast<size_t>(v);
    return true;
}
bool parse_uint64(const char* s, uint64_t& out) {
    if (!s) return false;
    char* endp = nullptr;
    unsigned long long v = std::strtoull(s, &endp, 10);
    if (!endp || *endp != '\0' || endp == s) return false;
    out = static_cast<uint64_t>(v);
    return true;
}
bool parse_int(const char* s, int& out) {
    if (!s) return false;
    char* endp = nullptr;
    long v = std::strtol(s, &endp, 10);
    if (!endp || *endp != '\0' || endp == s) return false;
    out = static_cast<int>(v);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage_short();
        return 2; // INVALID_ARGUMENT
    }
    // Help requested
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--help" || s == "-h") {
            brute::print_help(std::cout);
            return 0;
        }
    }
    // First positional arg = wallet path
    std::string wallet_path = argv[1];
    if (wallet_path.empty() || wallet_path[0] == '-') {
        usage_short();
        return 2;
    }
    if (!util::file_exists(wallet_path)) {
        std::cerr << "Error: file not found: " << wallet_path << "\n";
        return 3; // FILE_NOT_FOUND
    }
    if (!util::is_regular_file(wallet_path)) {
        std::cerr << "Error: not a regular file: " << wallet_path << "\n";
        return 3;
    }

    brute::Config cfg;
    cfg.wallet_path = wallet_path;
    cfg.threads = std::thread::hardware_concurrency();
    if (cfg.threads == 0) cfg.threads = 1;

    // Default mode: alnum brute force
    std::string mode = "alnum";

    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) return nullptr;
            return argv[++i];
        };
        if (s == "--mode")            { const char* v = next(); if (!v) { std::cerr << "--mode needs an argument\n"; return 2; } mode = v; }
        else if (s == "--charset")   { const char* v = next(); if (!v) { std::cerr << "--charset needs an argument\n"; return 2; } mode = "custom"; cfg.charset = v; }
        else if (s == "--min-len")   { const char* v = next(); if (!v) { std::cerr << "--min-len needs an argument\n"; return 2; } if (!parse_size(v, cfg.min_len)) { std::cerr << "bad --min-len\n"; return 2; } }
        else if (s == "--max-len")   { const char* v = next(); if (!v) { std::cerr << "--max-len needs an argument\n"; return 2; } if (!parse_size(v, cfg.max_len)) { std::cerr << "bad --max-len\n"; return 2; } }
        else if (s == "--prefix")    { const char* v = next(); if (!v) { std::cerr << "--prefix needs an argument\n"; return 2; } cfg.prefix = v; }
        else if (s == "--suffix")    { const char* v = next(); if (!v) { std::cerr << "--suffix needs an argument\n"; return 2; } cfg.suffix = v; }
        else if (s == "--threads")   { const char* v = next(); if (!v) { std::cerr << "--threads needs an argument\n"; return 2; } if (!parse_size(v, cfg.threads)) { std::cerr << "bad --threads\n"; return 2; } }
        else if (s == "--wordlist")  { const char* v = next(); if (!v) { std::cerr << "--wordlist needs an argument\n"; return 2; } cfg.wordlist_path = v; }
        else if (s == "--mask")      { const char* v = next(); if (!v) { std::cerr << "--mask needs an argument\n"; return 2; } cfg.mask = v; }
        else if (s == "--custom1" || s == "--custom-charset-1") { const char* v = next(); if (!v) { std::cerr << "--custom1 needs an argument\n"; return 2; } cfg.custom1 = v; }
        else if (s == "--custom2" || s == "--custom-charset-2") { const char* v = next(); if (!v) { std::cerr << "--custom2 needs an argument\n"; return 2; } cfg.custom2 = v; }
        else if (s == "--resume")     { cfg.resume = true; }
        else if (s == "--no-resume")  { cfg.no_resume = true; }
        else if (s == "--state-file"){ const char* v = next(); if (!v) { std::cerr << "--state-file needs an argument\n"; return 2; } cfg.state_file = v; }
        else if (s == "--tried-file"){ const char* v = next(); if (!v) { std::cerr << "--tried-file needs an argument\n"; return 2; } cfg.tried_file = v; }
        else if (s == "--result-file"){ const char* v = next(); if (!v) { std::cerr << "--result-file needs an argument\n"; return 2; } cfg.result_file = v; }
        else if (s == "--state-interval"){ const char* v = next(); if (!v) { std::cerr << "--state-interval needs an argument\n"; return 2; } if (!parse_int(v, cfg.state_interval_sec)) { std::cerr << "bad --state-interval\n"; return 2; } }
        else if (s == "--progress-interval"){ const char* v = next(); if (!v) { std::cerr << "--progress-interval needs an argument\n"; return 2; } if (!parse_int(v, cfg.progress_interval_sec)) { std::cerr << "bad --progress-interval\n"; return 2; } }
        else if (s == "--max-attempts"){ const char* v = next(); if (!v) { std::cerr << "--max-attempts needs an argument\n"; return 2; } if (!parse_uint64(v, cfg.max_attempts)) { std::cerr << "bad --max-attempts\n"; return 2; } }
        else if (s == "--json")     { cfg.json = true; cfg.quiet = false; }
        else if (s == "--quiet" || s == "-q") { cfg.quiet = true; }
        else if (s == "--help" || s == "-h") { brute::print_help(std::cout); return 0; }
        else {
            std::cerr << "Unknown option: " << s << "\n";
            usage_short();
            return 2;
        }
    }

    // Validate mode interactions
    int mode_count = 0;
    if (!cfg.mask.empty())          ++mode_count;
    if (!cfg.wordlist_path.empty()) ++mode_count;
    // Brute mode is the implicit default if neither mask nor wordlist is set
    bool is_brute = (cfg.mask.empty() && cfg.wordlist_path.empty());
    if (is_brute) ++mode_count;

    if (mode_count > 1) {
        std::cerr << "Error: --mask, --wordlist, and --mode/--charset are mutually "
                     "exclusive. Pick one search mode.\n";
        return 2;
    }

    if (is_brute) {
        if (cfg.max_len < cfg.min_len) {
            std::cerr << "Error: --max-len (" << cfg.max_len
                      << ") < --min-len (" << cfg.min_len << ")\n";
            return 2;
        }
        if (cfg.max_len == 0) {
            std::cerr << "Error: --max-len is required in brute mode\n";
            return 2;
        }
        if (cfg.min_len == 0) cfg.min_len = 1;
        if (cfg.charset.empty()) {
            cfg.charset = brute::resolve_charset(mode);
        }
        if (cfg.charset.empty()) {
            std::cerr << "Error: empty charset (mode='" << mode << "'?)\n";
            return 2;
        }
    } else if (!cfg.mask.empty()) {
        // Mask mode: parse it early to surface errors before running
        std::string merr;
        auto slots = brute::parse_mask(cfg, merr);
        if (!merr.empty()) {
            std::cerr << "Error: invalid mask: " << merr << "\n";
            return 2;
        }
        (void)slots;
    } else if (!cfg.wordlist_path.empty()) {
        if (!util::file_exists(cfg.wordlist_path)) {
            std::cerr << "Error: wordlist not found: " << cfg.wordlist_path << "\n";
            return 3;
        }
    }

    if (cfg.threads == 0) cfg.threads = 1;

    // Run!
    brute::Result r = brute::run_brute(cfg);

    if (!r.errors.empty()) {
        for (auto& e : r.errors) std::cerr << "Error: " << e << "\n";
        return 1; // GENERAL_ERROR
    }
    if (r.found) {
        return 0; // SUCCESS
    }
    // Distinguish exhausted vs. interrupted — check the SIGINT flag.
    // (the brute module sets this when handling Ctrl-C)
    return 5; // search exhausted
}
