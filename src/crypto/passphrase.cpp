// src/crypto/passphrase.cpp
#include "btclegacy/crypto/passphrase.h"
#include "btclegacy/util/file_util.h"
#include "btclegacy/util/strings.h"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace btclegacy::crypto {

namespace {
// Read one line from stdin without echoing.
//   POSIX: disable ECHO via termios, then read via fgetc(stdin).
//   Windows: read character-by-character via _getch() (no echo by default).
bool read_hidden_line(std::string& out) {
    out.clear();
#ifdef _WIN32
    bool is_tty = _isatty(_fileno(stdin)) != 0;
    if (is_tty) {
        std::fputs("Enter wallet passphrase: ", stderr);
        std::fflush(stderr);
        std::string line;
        int c;
        while ((c = _getch()) != EOF) {
            if (c == '\r' || c == '\n') break;
            // Function/arrow keys on Windows return 0 or 0xE0 first,
            // followed by a scan code — discard the next byte.
            if (c == 0 || c == 0xE0) {
                (void)_getch();
                continue;
            }
            // Backspace: remove the last character from the buffer.
            if (c == 0x08) {
                if (!line.empty()) line.pop_back();
                continue;
            }
            line.push_back(char(c));
        }
        std::fputc('\n', stderr);
        std::fflush(stderr);
        out.swap(line);
    } else {
        // Not a TTY (e.g., piped stdin): read a line normally.
        std::string line;
        int c;
        while ((c = std::fgetc(stdin)) != EOF) {
            if (c == '\n' || c == '\r') break;
            line.push_back(char(c));
        }
        out.swap(line);
    }
    return true;
#else
    bool is_tty = isatty(STDIN_FILENO) != 0;
    termios old{};
    bool restored = false;
    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &old) != 0) {
            is_tty = false;
        } else {
            termios nw = old;
            nw.c_lflag &= ~(ECHO);
            if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &nw) != 0) is_tty = false;
            else restored = true;
        }
    }
    std::string line;
    if (is_tty) std::fputs("Enter wallet passphrase: ", stderr);
    std::fflush(stderr);
    int c;
    while ((c = std::fgetc(stdin)) != EOF) {
        if (c == '\n' || c == '\r') break;
        line.push_back(char(c));
    }
    if (is_tty) {
        std::fputc('\n', stderr);
        std::fflush(stderr);
    }
    if (restored) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    out.swap(line);
    return true;
#endif
}
} // namespace

bool acquire_passphrase(const PassphraseRequest& req,
                          platform::SecureBuffer& out,
                          std::string& err) {
    out.clear();
    if (req.has_passphrase_arg) {
        out = platform::SecureBuffer::from_string(req.passphrase_arg);
        return true;
    }
    if (req.has_passphrase_file) {
        std::vector<uint8_t> data;
        if (!util::read_all(req.passphrase_file, data)) {
            err = "cannot read passphrase file: " + req.passphrase_file;
            return false;
        }
        // Strip a single trailing newline if present.
        while (!data.empty() && (data.back() == '\n' || data.back() == '\r')) {
            data.pop_back();
        }
        out = platform::SecureBuffer(data.data(), data.size());
        platform::secure_wipe(data.data(), data.size());
        return true;
    }
    if (req.passphrase_stdin) {
        std::string line;
        std::getline(std::cin, line); // read one line, no echo to stdout
        out = platform::SecureBuffer::from_string(line);
        platform::secure_wipe(&line[0], line.size());
        return true;
    }
    // Interactive
    std::string line;
    if (!read_hidden_line(line)) {
        err = "failed to read passphrase from terminal";
        return false;
    }
    out = platform::SecureBuffer::from_string(line);
    platform::secure_wipe(&line[0], line.size());
    return true;
}

} // namespace btclegacy::crypto
