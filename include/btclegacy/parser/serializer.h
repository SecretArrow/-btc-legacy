// btclegacy/parser/serializer.h
#pragma once
//
// Compact C++20 byte-stream serializer compatible with the historical
// Bitcoin Core "CDataStream" / "ADD_SERIALIZE_METHODS" pattern.
//
// The Bitcoin Core wallet stores variable-length items in CDataStream
// format: little-endian integers, length-prefixed byte arrays where
// the length is encoded as a CompactSize (varint), fixed-size blobs
// (raw bytes), fixed-size integers (LE), and string=vector<uint8_t>.
//
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>

namespace btclegacy::parser {

class Serializer {
public:
    Serializer() = default;
    explicit Serializer(std::vector<uint8_t> v) : buf_(std::move(v)) {}
    explicit Serializer(const std::string& s) : buf_(s.begin(), s.end()) {}

    void clear() { buf_.clear(); }
    const std::vector<uint8_t>& buffer() const { return buf_; }
    std::vector<uint8_t> take() { return std::move(buf_); }
    size_t size() const { return buf_.size(); }
    bool empty() const { return buf_.empty(); }
    bool eof() const { return pos_ >= buf_.size(); }
    size_t pos() const { return pos_; }

    // ---- Write API ----
    void put(uint8_t b) { buf_.push_back(b); }
    void put_bytes(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); }
    void put_u16(uint16_t v) { put_bytes(reinterpret_cast<const uint8_t*>(&v), 2); }
    void put_u32(uint32_t v) { put_bytes(reinterpret_cast<const uint8_t*>(&v), 4); }
    void put_u64(uint64_t v) { put_bytes(reinterpret_cast<const uint8_t*>(&v), 8); }
    void put_i64(int64_t v) { put_bytes(reinterpret_cast<const uint8_t*>(&v), 8); }

    // CompactSize (varint) — same algorithm as Bitcoin Core.
    void put_compact_size(uint64_t n);
    void put_string(const std::string& s);
    void put_bytes_prefixed(const std::vector<uint8_t>& v);

    // ---- Read API ----
    uint8_t read_u8();
    uint16_t read_u16();
    uint32_t read_u32();
    uint64_t read_u64();
    int64_t read_i64();

    uint64_t read_compact_size();
    std::string read_string();
    std::vector<uint8_t> read_bytes_prefixed();
    std::vector<uint8_t> read_bytes(size_t n);

    // Raw remaining view
    std::vector<uint8_t> remaining() const;

private:
    std::vector<uint8_t> buf_;
    size_t pos_ = 0;
};

} // namespace btclegacy::parser
