// src/cli/cli_dispatch.cpp
//
// Minimal argv parser + dispatcher. We deliberately avoid pulling in
// CLI11 / cxxopts — the supported flag set is small enough that a
// hand-rolled parser keeps the binary dependency-free and easy to
// audit for security-sensitive tooling.
//
#include "btclegacy/cli/cli_dispatch.h"
#include "btclegacy/util/exit_codes.h"
#include "btclegacy/util/strings.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <string>

namespace btclegacy::cli {

// Globals that get set by each subcommand's flag pre-pass.
bool g_json_mode    = false;
bool g_verbose_mode = false;
bool g_quiet_mode   = false;

// Declarations of the per-command entry points (defined in their own files)
int cmd_detect(int argc, char** argv);
int cmd_info(int argc, char** argv);
int cmd_inspect(int argc, char** argv);
int cmd_validate(int argc, char** argv);
int cmd_backup(int argc, char** argv);
int cmd_create(int argc, char** argv);
int cmd_password(int argc, char** argv);
int cmd_export(int argc, char** argv);
int cmd_recover(int argc, char** argv);
int cmd_migrate(int argc, char** argv);
int cmd_version(int argc, char** argv);
int cmd_hashdump(int argc, char** argv);

void print_top_usage() {
    std::cerr <<
        "btc-legacy — Bitcoin Legacy Wallet CLI (2009–2015 wallet.dat tooling)\n"
        "\n"
        "Usage: btc-legacy <command> [args] [options]\n"
        "\n"
        "Global options:\n"
        "  --help, -h           Show this help and exit\n"
        "  --version            Print version and exit\n"
        "  --json               Emit JSON output (no progress, no decorative text)\n"
        "  --verbose            Verbose diagnostics to stderr\n"
        "  --quiet              Suppress progress and decorations\n"
        "\n"
        "Commands:\n"
        "  detect <wallet>          Detect wallet type and encryption status\n"
        "  info <wallet>           Show safe metadata about the wallet\n"
        "  inspect <wallet>        Inspect individual wallet records (redacted)\n"
        "  validate <wallet>       Verify wallet integrity\n"
        "  backup <wallet>         Create a SHA-256-verified backup\n"
        "  create --year YYYY --out FILE   Generate a synthetic test wallet\n"
        "  password verify <wallet> [PASSPHRASE SOURCE]   Verify a passphrase\n"
        "  export <wallet> [EXPORT FLAGS] [PASSPHRASE SOURCE]\n"
        "                          Export addresses, public keys, transactions,\n"
        "                          or (with --private-keys) decrypted private keys\n"
        "  recover <wallet> [PASSPHRASE SOURCE]   Recover readable records\n"
        "  migrate <wallet> --out PATH [PASSPHRASE SOURCE]  Migrate wallet to JSON\n"
        "  hashdump <wallet>    Export hashcat mode 11300 hash (for GPU attack)\n"
        "  version                 Print version information\n"
        "\n"
        "Passphrase sources (for any command that needs wallet decryption):\n"
        "  --passphrase <value>            Direct argument (DANGEROUS in shell history)\n"
        "  --passphrase-file <path>         Read first line of file\n"
        "  --passphrase-stdin               Read first line from stdin (no echo)\n"
        "  (no flag)                        Interactive hidden prompt\n"
        "\n"
        "Exit codes: 0 SUCCESS | 1 GENERAL | 2 INVALID_ARG | 3 FILE_NOT_FOUND |\n"
        "            4 UNSUPPORTED | 5 CORRUPTED | 6 INCORRECT_PASSPHRASE |\n"
        "            7 PERMISSION | 8 MIGRATION_FAILED | 9 USER_CANCELLED\n";
}

// Parse common flags. Returns true if the flag was consumed (and updates i).
// Returns false for an unrecognized flag.
bool consume_global_flag(const char* arg, GlobalOptions& g) {
    if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
        g.help = true; return true;
    }
    if (std::strcmp(arg, "--version") == 0) { g.version = true; return true; }
    if (std::strcmp(arg, "--json") == 0)    { g.json = true; return true; }
    if (std::strcmp(arg, "--verbose") == 0) { g.verbose = true; return true; }
    if (std::strcmp(arg, "--quiet") == 0 || std::strcmp(arg, "-q") == 0) {
        g.quiet = true; return true;
    }
    return false;
}

int dispatch(int argc, char** argv) {
    if (argc < 2) {
        print_top_usage();
        return ExitCode::INVALID_ARGUMENT;
    }
    // Check for top-level help / version before dispatching
    GlobalOptions g;
    for (int i = 1; i < argc; ++i) {
        if (consume_global_flag(argv[i], g)) continue;
        break; // first non-global flag = command
    }
    if (g.help) { print_top_usage(); return ExitCode::SUCCESS; }
    if (g.version) return cmd_version(argc, argv);

    std::string cmd = argv[1];
    if (cmd == "version")      return cmd_version(argc, argv);
    if (cmd == "detect")       return cmd_detect(argc, argv);
    if (cmd == "info")          return cmd_info(argc, argv);
    if (cmd == "inspect")       return cmd_inspect(argc, argv);
    if (cmd == "validate")      return cmd_validate(argc, argv);
    if (cmd == "backup")        return cmd_backup(argc, argv);
    if (cmd == "create")        return cmd_create(argc, argv);
    if (cmd == "password")      return cmd_password(argc, argv);
    if (cmd == "export")        return cmd_export(argc, argv);
    if (cmd == "recover")       return cmd_recover(argc, argv);
    if (cmd == "migrate")       return cmd_migrate(argc, argv);
    if (cmd == "hashdump")      return cmd_hashdump(argc, argv);

    std::cerr << "Unknown command: " << cmd << "\n";
    print_top_usage();
    return ExitCode::INVALID_ARGUMENT;
}

bool parse_passphrase_options(int argc, char** argv, int& i,
                                PassphraseOptions& out,
                                std::string& err) {
    const char* a = argv[i];
    if (std::strcmp(a, "--passphrase") == 0) {
        if (i + 1 >= argc) { err = "--passphrase needs a value"; return false; }
        out.has_arg = true;
        out.arg = argv[i+1];
        i += 2;
        return true;
    }
    if (std::strcmp(a, "--passphrase-file") == 0) {
        if (i + 1 >= argc) { err = "--passphrase-file needs a value"; return false; }
        out.has_file = true;
        out.file = argv[i+1];
        i += 2;
        return true;
    }
    if (std::strcmp(a, "--passphrase-stdin") == 0) {
        out.stdin_flag = true;
        i += 1;
        return true;
    }
    return false;
}

} // namespace btclegacy::cli
