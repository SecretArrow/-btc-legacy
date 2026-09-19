// btclegacy/util/strings.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace btclegacy::util {

// Hex helpers
std::string to_hex(const uint8_t* data, size_t len);
std::string to_hex(const std::vector<uint8_t>& v);
std::string to_hex(const std::string& s);
bool from_hex(const std::string& hex, std::vector<uint8_t>& out);

// String utilities
std::string trim(const std::string& s);
std::string to_lower(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);

// Redaction
std::string redact(const std::string& s, size_t prefix_chars = 4);

} // namespace btclegacy::util
