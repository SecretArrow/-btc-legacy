// tests/unit/test_serializer.cpp
#include "test_macros.h"
#include "btclegacy/parser/serializer.h"
#include <string>
#include <vector>
#include <cstring>

using namespace btclegacy::parser;

TEST(ser_u32_roundtrip) {
    Serializer w;
    w.put_u32(60000);
    Serializer r(w.buffer());
    uint32_t v = r.read_u32();
    EXPECT(v == 60000);
}

TEST(ser_varint_short) {
    Serializer w;
    w.put_compact_size(42);
    Serializer r(w.buffer());
    EXPECT(r.read_compact_size() == 42);
}

TEST(ser_varint_medium) {
    Serializer w;
    w.put_compact_size(0x1234);
    Serializer r(w.buffer());
    EXPECT(r.read_compact_size() == 0x1234);
}

TEST(ser_varint_large) {
    Serializer w;
    w.put_compact_size(0x10000000);
    Serializer r(w.buffer());
    EXPECT(r.read_compact_size() == 0x10000000);
}

TEST(ser_string_roundtrip) {
    Serializer w;
    w.put_string("Hello, Bitcoin");
    Serializer r(w.buffer());
    std::string s = r.read_string();
    EXPECT_STR_EQ(s, "Hello, Bitcoin");
}

TEST(ser_bytes_prefixed_roundtrip) {
    Serializer w;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    w.put_bytes_prefixed(data);
    Serializer r(w.buffer());
    std::vector<uint8_t> out = r.read_bytes_prefixed();
    EXPECT(out.size() == data.size());
    for (size_t i = 0; i < data.size(); ++i) EXPECT(out[i] == data[i]);
}

TEST(ser_eof_throws) {
    Serializer w;
    w.put_u32(0);
    Serializer r(w.buffer());
    (void)r.read_u32(); // first read OK
    bool thrown = false;
    try { (void)r.read_u32(); } catch (...) { thrown = true; }
    EXPECT(thrown);
}
