// src/parser/serializer.cpp
#include "btclegacy/parser/serializer.h"
#include <stdexcept>
#include <cstring>

namespace btclegacy::parser {

void Serializer::put_compact_size(uint64_t n) {
    if (n < 253) {
        buf_.push_back(uint8_t(n));
    } else if (n <= 0xffff) {
        buf_.push_back(253);
        buf_.push_back(uint8_t(n & 0xff));
        buf_.push_back(uint8_t((n >> 8) & 0xff));
    } else if (n <= 0xffffffff) {
        buf_.push_back(254);
        buf_.push_back(uint8_t(n & 0xff));
        buf_.push_back(uint8_t((n >> 8) & 0xff));
        buf_.push_back(uint8_t((n >> 16) & 0xff));
        buf_.push_back(uint8_t((n >> 24) & 0xff));
    } else {
        buf_.push_back(255);
        for (int i = 0; i < 8; ++i)
            buf_.push_back(uint8_t((n >> (i*8)) & 0xff));
    }
}

void Serializer::put_string(const std::string& s) {
    put_compact_size(s.size());
    buf_.insert(buf_.end(), s.begin(), s.end());
}

void Serializer::put_bytes_prefixed(const std::vector<uint8_t>& v) {
    put_compact_size(v.size());
    buf_.insert(buf_.end(), v.begin(), v.end());
}

uint8_t Serializer::read_u8() {
    if (pos_ + 1 > buf_.size()) throw std::runtime_error("u8 oob");
    return buf_[pos_++];
}
uint16_t Serializer::read_u16() {
    if (pos_ + 2 > buf_.size()) throw std::runtime_error("u16 oob");
    uint16_t v = uint16_t(buf_[pos_]) | (uint16_t(buf_[pos_+1]) << 8);
    pos_ += 2; return v;
}
uint32_t Serializer::read_u32() {
    if (pos_ + 4 > buf_.size()) throw std::runtime_error("u32 oob");
    uint32_t v = uint32_t(buf_[pos_]) | (uint32_t(buf_[pos_+1]) << 8) |
                 (uint32_t(buf_[pos_+2]) << 16) | (uint32_t(buf_[pos_+3]) << 24);
    pos_ += 4; return v;
}
uint64_t Serializer::read_u64() {
    if (pos_ + 8 > buf_.size()) throw std::runtime_error("u64 oob");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t(buf_[pos_ + i]) << (i*8));
    pos_ += 8; return v;
}
int64_t Serializer::read_i64() {
    return int64_t(read_u64());
}

uint64_t Serializer::read_compact_size() {
    if (pos_ + 1 > buf_.size()) throw std::runtime_error("varint oob");
    uint8_t first = buf_[pos_++];
    if (first < 253) return first;
    if (first == 253) {
        if (pos_ + 2 > buf_.size()) throw std::runtime_error("varint16 oob");
        uint16_t v = uint16_t(buf_[pos_]) | (uint16_t(buf_[pos_+1]) << 8);
        pos_ += 2; return v;
    }
    if (first == 254) {
        if (pos_ + 4 > buf_.size()) throw std::runtime_error("varint32 oob");
        uint32_t v = uint32_t(buf_[pos_]) | (uint32_t(buf_[pos_+1]) << 8) |
                     (uint32_t(buf_[pos_+2]) << 16) | (uint32_t(buf_[pos_+3]) << 24);
        pos_ += 4; return v;
    }
    if (pos_ + 8 > buf_.size()) throw std::runtime_error("varint64 oob");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t(buf_[pos_ + i]) << (i*8));
    pos_ += 8; return v;
}

std::string Serializer::read_string() {
    uint64_t n = read_compact_size();
    if (pos_ + n > buf_.size()) throw std::runtime_error("string oob");
    std::string s(reinterpret_cast<const char*>(buf_.data() + pos_), size_t(n));
    pos_ += n;
    return s;
}

std::vector<uint8_t> Serializer::read_bytes_prefixed() {
    uint64_t n = read_compact_size();
    if (pos_ + n > buf_.size()) throw std::runtime_error("bytes_prefixed oob");
    std::vector<uint8_t> v(buf_.begin() + pos_, buf_.begin() + pos_ + n);
    pos_ += size_t(n);
    return v;
}

std::vector<uint8_t> Serializer::read_bytes(size_t n) {
    if (pos_ + n > buf_.size()) throw std::runtime_error("bytes oob");
    std::vector<uint8_t> v(buf_.begin() + pos_, buf_.begin() + pos_ + n);
    pos_ += n;
    return v;
}

std::vector<uint8_t> Serializer::remaining() const {
    if (pos_ >= buf_.size()) return {};
    return std::vector<uint8_t>(buf_.begin() + pos_, buf_.end());
}

} // namespace btclegacy::parser
