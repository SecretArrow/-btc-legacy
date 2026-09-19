// src/util/strings.cpp
#include "btclegacy/util/strings.h"
#include <algorithm>
#include <cctype>

namespace btclegacy::util {

static const char* hexdig = "0123456789abcdef";
std::string to_hex(const uint8_t* data, size_t len) {
    std::string s; s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(hexdig[data[i] >> 4]);
        s.push_back(hexdig[data[i] & 0x0f]);
    }
    return s;
}
std::string to_hex(const std::vector<uint8_t>& v) { return to_hex(v.data(), v.size()); }
std::string to_hex(const std::string& s) { return to_hex(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]); int lo = nib(hex[i+1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return true;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b - a);
}

std::string to_lower(const std::string& s) {
    std::string r; r.reserve(s.size());
    for (char c : s) r.push_back((char)std::tolower((unsigned char)c));
    return r;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    if (s.size() < prefix.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), s.begin());
}
bool ends_with(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

std::string redact(const std::string& s, size_t prefix_chars) {
    if (s.empty()) return "";
    std::string out(s.size(), '*');
    if (prefix_chars && prefix_chars < s.size()) {
        for (size_t i = 0; i < prefix_chars; ++i) out[i] = s[i];
        if (prefix_chars + 1 < s.size()) out[prefix_chars] = '*';
    }
    return out;
}

} // namespace btclegacy::util
