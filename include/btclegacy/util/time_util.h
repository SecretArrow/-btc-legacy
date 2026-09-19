// btclegacy/util/time_util.h
#pragma once
#include <cstdint>
#include <string>

namespace btclegacy::util {

uint64_t now_unix_seconds();
std::string format_timestamp(uint64_t unix_seconds, const std::string& fmt = "%Y%m%d-%H%M%S");
std::string format_datetime_iso(uint64_t unix_seconds);

} // namespace btclegacy::util
