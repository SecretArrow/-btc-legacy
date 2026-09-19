// tests/unit/test_main.cpp
#include "test_macros.h"
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    auto& all = btclegacy_test::registry();
    if (all.empty()) {
        std::cout << "No tests registered!\n";
        return 1;
    }
    int passed = 0;
    for (const auto& t : all) {
        int before = btclegacy_test::failure_count();
        std::cout << "[ RUN ] " << t.name << "\n";
        t.fn();
        int after = btclegacy_test::failure_count();
        if (after == before) { ++passed; std::cout << "[ OK  ] " << t.name << "\n"; }
        else                 { std::cout << "[ FAIL] " << t.name << "\n"; }
    }
    int failed = btclegacy_test::failure_count();
    std::cout << passed << "/" << all.size() << " tests passed, " << failed << " failures.\n";
    return failed == 0 ? 0 : 1;
}
