// btclegacy/util/file_util.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace btclegacy::util {

bool file_exists(const std::string& path);
bool is_regular_file(const std::string& path);
uint64_t file_size(const std::string& path);
bool read_all(const std::string& path, std::vector<uint8_t>& out);
bool write_all(const std::string& path, const std::vector<uint8_t>& data);
bool copy_file(const std::string& src, const std::string& dst);
bool touch(const std::string& path);

} // namespace btclegacy::util
