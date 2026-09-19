// tests/unit/test_macros.h
#pragma once
#include <cstdio>
#include <iostream>
#include <vector>
#include <string>
#include <string_view>

namespace btclegacy_test {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> v;
    return v;
}
inline int& failure_count() {
    static int f = 0;
    return f;
}

struct Registrar {
    Registrar(const char* name, void(*fn)()) {
        registry().push_back({name, fn});
    }
};

} // namespace btclegacy_test

#define TEST(name) \
    static void test_##name(); \
    static ::btclegacy_test::Registrar reg_##name(#name, test_##name); \
    static void test_##name()

#define EXPECT(cond) \
    do { if (!(cond)) { \
        std::cerr << "  FAIL " << #cond << " (line " << __LINE__ << ")\n"; \
        ::btclegacy_test::failure_count()++; return; \
    } } while (0)

#define EXPECT_EQ(a, b) \
    do { auto _x = (a); auto _y = (b); \
    if (!(_x == _y)) { \
        std::cerr << "  FAIL " #a " == " #b " (line " << __LINE__ << ")\n"; \
        ::btclegacy_test::failure_count()++; return; \
    } } while (0)

#define EXPECT_STR_EQ(a, b) \
    do { std::string _xs = (a); std::string _ys = (b); \
    if (!(_xs == _ys)) { \
        std::cerr << "  FAIL " #a " == " #b "\n  got: " << _xs << "\n  exp: " << _ys << "\n"; \
        ::btclegacy_test::failure_count()++; return; \
    } } while (0)
