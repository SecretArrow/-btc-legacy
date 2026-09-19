// btclegacy/platform/secure_memory.h
#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace btclegacy::platform {

/// Best-effort secure byte buffer. Attempts to mlock() memory and
/// always wipes (volatile memset) on destruction.
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t n) : buf_(n) {}
    SecureBuffer(const uint8_t* p, size_t n) : buf_(p, p + n) {}
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&);
    SecureBuffer& operator=(const SecureBuffer&);

    SecureBuffer(SecureBuffer&&) noexcept = default;
    SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

    uint8_t* data() { return buf_.data(); }
    const uint8_t* data() const { return buf_.data(); }
    size_t size() const { return buf_.size(); }
    bool empty() const { return buf_.empty(); }
    void clear() { wipe(); buf_.clear(); }
    void resize(size_t n);
    void wipe(); // volatile memset, called on dtor

    // Best-effort attempt to lock pages into RAM (mlock/VirtualLock)
    bool try_lock();
    void unlock();

    // Get as std::string (without leaving secrets in malloc)
    std::string as_string() const;
    static SecureBuffer from_string(const std::string& s);

private:
    std::vector<uint8_t> buf_;
    bool locked_ = false;
};

// Wipe a raw buffer (volatile memset)
void secure_wipe(void* p, size_t n);

} // namespace btclegacy::platform
