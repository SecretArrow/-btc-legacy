// src/util/time_util.cpp
#include "btclegacy/util/time_util.h"
#include <ctime>
#include <sstream>
#include <iomanip>

namespace btclegacy::util {

uint64_t now_unix_seconds() {
    return uint64_t(std::time(nullptr));
}

std::string format_timestamp(uint64_t unix_seconds, const std::string& fmt) {
    std::time_t t = (std::time_t)unix_seconds;
    std::tm tm{}; gmtime_r(&t, &tm);
    std::ostringstream os; os << std::put_time(&tm, fmt.c_str());
    return os.str();
}

std::string format_datetime_iso(uint64_t unix_seconds) {
    return format_timestamp(unix_seconds, "%Y-%m-%dT%H:%M:%SZ");
}

} // namespace btclegacy::util
