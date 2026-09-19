// src/util/file_util.cpp
#include "btclegacy/util/file_util.h"
#include <sys/stat.h>
#include <fstream>
#include <cstring>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#endif

// MinGW-w64's <sys/stat.h> defines S_ISREG, but older MinGW.org does not.
// Define a defensive fallback so is_regular_file() compiles everywhere.
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

namespace btclegacy::util {

bool file_exists(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return true;
}
bool is_regular_file(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISREG(st.st_mode);
}
uint64_t file_size(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return 0;
    return (uint64_t)st.st_size;
}
bool read_all(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto sz = (std::streamoff)f.tellg();
    if (sz < 0) return false;
    out.resize((size_t)sz);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good() || f.eof();
}
bool write_all(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
    return f.good();
}
bool copy_file(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << in.rdbuf();
    return out.good();
}
bool touch(const std::string& path) {
    std::ofstream f(path, std::ios::out | std::ios::app);
    return f.good();
}

} // namespace btclegacy::util
