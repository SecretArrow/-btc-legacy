// btclegacy/cli/cli_dispatch.h
#pragma once
#include "btclegacy/util/exit_codes.h"
#include <string>
#include <vector>

namespace btclegacy::cli {

struct GlobalOptions {
    bool json = false;
    bool verbose = false;
    bool quiet = false;
    bool help = false;
    bool version = false;
};

// Main dispatch entry point. Parses argv, dispatches to the
// matching command handler, returns the exit code.
int dispatch(int argc, char** argv);

// Common passphrase-source option parser used by every command that
// needs to decrypt wallet data. Returns false on argument error.
struct PassphraseOptions {
    bool        has_arg = false; std::string arg;
    bool        has_file = false; std::string file;
    bool        stdin_flag = false;
    bool        any_set() const { return has_arg || has_file || stdin_flag; }
};

bool parse_passphrase_options(int argc, char** argv, int& i,
                              PassphraseOptions& out,
                              std::string& err);

// Print usage for the top-level binary
void print_top_usage();

} // namespace btclegacy::cli
