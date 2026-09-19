// src/platform/secure_memory.cpp
#include "btclegacy/platform/secure_memory.h"
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace btclegacy::platform {

void secure_wipe(void* p, size_t n) {
    if (!p || n == 0) return;
    volatile uint8_t* vp = reinterpret_cast<volatile uint8_t*>(p);
    while (n--) *vp++ = 0;
}

SecureBuffer::SecureBuffer(const SecureBuffer& o) : buf_(o.buf_) {}
SecureBuffer& SecureBuffer::operator=(const SecureBuffer& o) {
    if (this != &o) {
        wipe();
        buf_ = o.buf_;
    }
    return *this;
}

SecureBuffer::~SecureBuffer() {
    wipe();
    if (locked_) unlock();
}

void SecureBuffer::resize(size_t n) {
    wipe();
    buf_.resize(n);
}

void SecureBuffer::wipe() {
    secure_wipe(buf_.data(), buf_.size());
}

bool SecureBuffer::try_lock() {
    if (locked_) return true;
#ifdef _WIN32
    locked_ = VirtualLock(buf_.data(), buf_.size()) != 0;
#else
    locked_ = mlock(buf_.data(), buf_.size()) == 0;
#endif
    return locked_;
}

void SecureBuffer::unlock() {
    if (!locked_) return;
#ifdef _WIN32
    VirtualUnlock(buf_.data(), buf_.size());
#else
    munlock(buf_.data(), buf_.size());
#endif
    locked_ = false;
}

std::string SecureBuffer::as_string() const {
    return std::string(reinterpret_cast<const char*>(buf_.data()), buf_.size());
}

SecureBuffer SecureBuffer::from_string(const std::string& s) {
    return SecureBuffer(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

} // namespace btclegacy::platform
