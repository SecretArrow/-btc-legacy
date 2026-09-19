// btclegacy/util/progress.h
#pragma once
#include <string>
#include <functional>

namespace btclegacy::util {

// Progress reporter. When `quiet` or `json` is set, the callback is a no-op.
class Progress {
public:
    Progress(bool quiet, bool json) : quiet_(quiet), json_(json) {}
    void update(int percent, const std::string& msg) const;
    void start(const std::string& msg) const;
    void finish(const std::string& msg) const;
private:
    bool quiet_;
    bool json_;
};

} // namespace btclegacy::util
