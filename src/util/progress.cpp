// src/util/progress.cpp
#include "btclegacy/util/progress.h"
#include <iostream>
#include <iomanip>

namespace btclegacy::util {

void Progress::start(const std::string& msg) const {
    if (quiet_ || json_) return;
    std::cerr << msg << "\n";
}
void Progress::update(int percent, const std::string& msg) const {
    if (quiet_ || json_) return;
    int p = percent < 0 ? 0 : (percent > 100 ? 100 : percent);
    std::cerr << "\r" << msg << " " << std::setw(3) << p << "%" << std::flush;
}
void Progress::finish(const std::string& msg) const {
    if (quiet_ || json_) return;
    std::cerr << "\r" << msg << " 100%\n";
}

} // namespace btclegacy::util
