// btclegacy/crypto/passphrase.h
#pragma once
//
// Passphrase acquisition — supports the four input methods required
// by the CLI spec:
//
//   1. --passphrase <value>          direct argument
//   2. (no flag)                     interactive hidden prompt
//   3. --passphrase-file <path>      read from file
//   4. --passphrase-stdin            read one line from stdin
//
// The returned SecureBuffer is zeroed when destroyed.
//
#include "btclegacy/platform/secure_memory.h"
#include <string>

namespace btclegacy::crypto {

struct PassphraseRequest {
    bool has_passphrase_arg   = false;
    std::string passphrase_arg;

    bool has_passphrase_file  = false;
    std::string passphrase_file;

    bool passphrase_stdin     = false;

    // for interactive prompt
    std::string prompt_text = "Enter wallet passphrase:";
};

// Acquire the passphrase according to the request, returning it as
// a SecureBuffer (zeroed on destruction).
//
// Returns true on success. On failure sets `err`.
// Never echoes the passphrase to stdout or stderr.
bool acquire_passphrase(const PassphraseRequest& req,
                        platform::SecureBuffer& out,
                        std::string& err);

} // namespace btclegacy::crypto
