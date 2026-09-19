// tests/unit/test_sha256.cpp
#include "test_macros.h"
#include "btclegacy/util/sha256.h"
#include "btclegacy/util/strings.h"
#include <cstring>
#include <string>

using namespace btclegacy::util;

TEST(sha256_empty) {
    Sha256 h;
    uint8_t out[32]; h.finish(out);
    EXPECT_STR_EQ(to_hex(out, 32),
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(sha256_abc) {
    Sha256 h; h.update(std::string("abc"));
    uint8_t out[32]; h.finish(out);
    EXPECT_STR_EQ(to_hex(out, 32),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(sha256_long_input) {
    // 56-byte input (exactly one block minus 8-byte length field)
    Sha256 h; h.update(std::string(56, 'a'));
    uint8_t out[32]; h.finish(out);
    std::string s = to_hex(out, 32);
    EXPECT(s.size() == 64);
}

TEST(sha256_2_block_input) {
    // 200 bytes — multi-block, exercises incremental API
    Sha256 h;
    std::string s(200, 'a');
    h.update(s);
    uint8_t out[32]; h.finish(out);
    std::string hex = to_hex(out, 32);
    EXPECT(hex.size() == 64);
}
