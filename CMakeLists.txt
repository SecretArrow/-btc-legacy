# ===========================================================================
#  btc-legacy — Bitcoin Legacy Wallet CLI (2009–2015 wallet.dat tooling)
# ===========================================================================
cmake_minimum_required(VERSION 3.16)
project(btc-legacy
    VERSION 1.0.0
    DESCRIPTION "Offline CLI tool for inspecting, validating and recovering legacy Bitcoin wallet.dat files"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Warning & hardening flags
# ---------------------------------------------------------------------------
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wformat=2
    -Wno-unused-parameter)

option(BTC_LEGACY_WERROR "Treat compiler warnings as errors" ON)
if(BTC_LEGACY_WERROR)
    add_compile_options(-Werror)
endif()

# ---------------------------------------------------------------------------
# Static linking — when ON, all four targets link OpenSSL statically so
# the resulting binaries are self-contained (no libssl/libcrypto .so or
# .dll dependency). Used by the GitHub Actions CI/release workflows.
# ---------------------------------------------------------------------------
option(BUILD_STATIC "Link OpenSSL statically into all targets" OFF)
if(BUILD_STATIC)
    # Tell CMake's FindOpenSSL module to prefer static .a archives over
    # shared .so / .dll. Works on Linux (finds /usr/lib/*/libssl.a) and
    # Windows MSYS2 (finds mingw-w64 static .a archives).
    set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL
        "Use static OpenSSL archives (.a)" FORCE)
endif()

option(BTC_LEGACY_ASAN  "Enable AddressSanitizer"  OFF)
option(BTC_LEGACY_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
if(BTC_LEGACY_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
endif()
if(BTC_LEGACY_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=undefined)
endif()

# ---------------------------------------------------------------------------
# OpenSSL
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# Helper: link OpenSSL to a target. Handles static vs shared based on
# BUILD_STATIC. On Linux static builds we bracket the OpenSSL archives
# with -Wl,-Bstatic / -Wl,-Bdynamic so even if FindOpenSSL falls back
# to -lssl/-lcrypto on some distros, we still pull the static lib, and
# subsequent libs (pthread, dl) stay shared. On Windows MinGW/MSYS2,
# FindOpenSSL with OPENSSL_USE_STATIC_LIBS=ON already picks up the
# static .a archives from the standard search path, so no bracketing
# is required.
# ---------------------------------------------------------------------------
function(btc_legacy_link_openssl target)
    if(BUILD_STATIC AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(${target} PRIVATE
            "-Wl,-Bstatic"
            OpenSSL::SSL OpenSSL::Crypto
            "-Wl,-Bdynamic"
            ${CMAKE_DL_LIBS})
    elseif(BUILD_STATIC AND MINGW)
        # MSYS2 static .a archives already resolved by FindOpenSSL.
        # OpenSSL 3.x static archives reference dlopen/dlsym on MinGW too.
        target_link_libraries(${target} PRIVATE
            OpenSSL::SSL OpenSSL::Crypto
            ${CMAKE_DL_LIBS})
    else()
        target_link_libraries(${target} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Source tree
# ---------------------------------------------------------------------------
set(BTC_LEGACY_SOURCES
    src/util/sha256.cpp
    src/util/strings.cpp
    src/util/time_util.cpp
    src/util/file_util.cpp
    src/util/json_writer.cpp
    src/util/progress.cpp
    src/platform/secure_memory.cpp
    src/bdb/bdb_database.cpp
    src/bdb/bdb_reader.cpp
    src/bdb/bdb_validator.cpp
    src/bdb/bdb_writer.cpp
    src/wallet/wallet_record.cpp
    src/wallet/wallet_parser.cpp
    src/wallet/wallet_version.cpp
    src/wallet/wallet_crypto.cpp
    src/crypto/key.cpp
    src/crypto/encryption.cpp
    src/crypto/passphrase.cpp
    src/crypto/secure_memory.cpp
    src/parser/serializer.cpp
    src/recovery/recover.cpp
    src/migration/migrate.cpp
    src/cli/cli_dispatch.cpp
    src/cli/cmd_detect.cpp
    src/cli/cmd_info.cpp
    src/cli/cmd_inspect.cpp
    src/cli/cmd_validate.cpp
    src/cli/cmd_backup.cpp
    src/cli/cmd_create.cpp
    src/cli/cmd_password.cpp
    src/cli/cmd_export.cpp
    src/cli/cmd_recover.cpp
    src/cli/cmd_migrate.cpp
    src/cli/cmd_hashdump.cpp
    src/cli/cmd_hashdump.cpp
    src/cli/cmd_version.cpp
    src/main.cpp
)

add_executable(btc-legacy ${BTC_LEGACY_SOURCES})
target_include_directories(btc-legacy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
btc_legacy_link_openssl(btc-legacy)

# OpenSSL 3.0 deprecated the EC_KEY_* and EVP_PKEY_from_EC_KEY_* APIs
# but the historical Bitcoin Core scheme we mirror relied on those
# (and the new EVP_PKEY API requires a different code path). Silence
# the deprecation warning just for the files that legitimately need
# the legacy EC API. NO general warning suppression is applied.
function(btc_legacy_apply_legacy_ec_suppression target)
    set_source_files_properties(src/crypto/key.cpp
        PROPERTIES COMPILE_OPTIONS -Wno-deprecated-declarations)
    set_source_files_properties(src/wallet/wallet_crypto.cpp
        PROPERTIES COMPILE_OPTIONS -Wno-deprecated-declarations)
    set_source_files_properties(src/crypto/encryption.cpp
        PROPERTIES COMPILE_OPTIONS -Wno-deprecated-declarations)
endfunction()

btc_legacy_apply_legacy_ec_suppression(btc-legacy)
btc_legacy_apply_legacy_ec_suppression(btc-legacy-unit-tests)
btc_legacy_apply_legacy_ec_suppression(btc-legacy-fuzz)

if(MSVC)
    target_compile_definitions(btc-legacy PRIVATE NOMINNOGNORE _CRT_SECURE_NO_WARNINGS)
else()
    target_link_libraries(btc-legacy PRIVATE pthread)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS btc-legacy RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# btc-legacy-brute — multi-threaded offline brute-force passphrase
# recovery for legacy Bitcoin wallet.dat. Reuses the same wallet/bdb/
# crypto source tree as btc-legacy but is shipped as a separate binary
# so the primary inspection tool stays free of recovery-mode knobs.
# ---------------------------------------------------------------------------
add_executable(btc-legacy-brute
    src/util/sha256.cpp
    src/util/strings.cpp
    src/util/time_util.cpp
    src/util/file_util.cpp
    src/util/json_writer.cpp
    src/util/progress.cpp
    src/platform/secure_memory.cpp
    src/bdb/bdb_database.cpp
    src/bdb/bdb_reader.cpp
    src/bdb/bdb_validator.cpp
    src/bdb/bdb_writer.cpp
    src/wallet/wallet_record.cpp
    src/wallet/wallet_parser.cpp
    src/wallet/wallet_version.cpp
    src/wallet/wallet_crypto.cpp
    src/crypto/key.cpp
    src/crypto/encryption.cpp
    src/crypto/passphrase.cpp
    src/crypto/secure_memory.cpp
    src/parser/serializer.cpp
    src/brute/brute.cpp
    src/brute/main.cpp
)
target_include_directories(btc-legacy-brute PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
btc_legacy_link_openssl(btc-legacy-brute)
if(NOT MSVC)
    target_link_libraries(btc-legacy-brute PRIVATE pthread)
endif()
# OpenSSL 3.0 deprecation suppression on the same files as btc-legacy
btc_legacy_apply_legacy_ec_suppression(btc-legacy-brute)
install(TARGETS btc-legacy-brute RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
enable_testing()

# Simple standalone test runner: built into the same translation unit list
# as the main library code. Uses a tiny assert-based framework to avoid
# pulling in GoogleTest (which is not available offline in this env).
add_executable(btc-legacy-unit-tests
    src/util/sha256.cpp
    src/util/strings.cpp
    src/util/time_util.cpp
    src/util/file_util.cpp
    src/util/json_writer.cpp
    src/util/progress.cpp
    src/platform/secure_memory.cpp
    src/bdb/bdb_database.cpp
    src/bdb/bdb_reader.cpp
    src/bdb/bdb_validator.cpp
    src/bdb/bdb_writer.cpp
    src/wallet/wallet_record.cpp
    src/wallet/wallet_parser.cpp
    src/wallet/wallet_version.cpp
    src/wallet/wallet_crypto.cpp
    src/crypto/key.cpp
    src/crypto/encryption.cpp
    src/crypto/passphrase.cpp
    src/crypto/secure_memory.cpp
    src/parser/serializer.cpp
    src/recovery/recover.cpp
    src/migration/migrate.cpp
    src/cli/cli_dispatch.cpp
    src/cli/cmd_detect.cpp
    src/cli/cmd_info.cpp
    src/cli/cmd_inspect.cpp
    src/cli/cmd_validate.cpp
    src/cli/cmd_backup.cpp
    src/cli/cmd_create.cpp
    src/cli/cmd_password.cpp
    src/cli/cmd_export.cpp
    src/cli/cmd_recover.cpp
    src/cli/cmd_migrate.cpp
    src/cli/cmd_hashdump.cpp
    src/cli/cmd_version.cpp
    tests/unit/test_main.cpp
    tests/unit/test_sha256.cpp
    tests/unit/test_bdb_writer_reader.cpp
    tests/unit/test_wallet_records.cpp
    tests/unit/test_passphrase.cpp
    tests/unit/test_serializer.cpp
)
target_include_directories(btc-legacy-unit-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
btc_legacy_link_openssl(btc-legacy-unit-tests)
if(NOT MSVC)
    target_link_libraries(btc-legacy-unit-tests PRIVATE pthread)
endif()

add_test(NAME unit-tests COMMAND btc-legacy-unit-tests)

# Integration tests run against the freshly built binary.
add_test(NAME integration-detect
    COMMAND btc-legacy detect
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/2012/unencrypted.wallet.dat)
add_test(NAME integration-info
    COMMAND btc-legacy info
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/2012/unencrypted.wallet.dat
        --json)
add_test(NAME integration-passphrase-correct
    COMMAND btc-legacy password verify
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/2012/encrypted.wallet.dat
        --passphrase "test-password")
add_test(NAME integration-passphrase-wrong
    COMMAND btc-legacy password verify
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/2012/encrypted.wallet.dat
        --passphrase "wrong"
        --json)
# This test asserts that an INCORRECT passphrase yields exit code 6
# (INCORRECT_PASSPHRASE). ctest treats non-zero exit as failure, so we
# invert the meaning: WILL_FAIL TRUE means "expected to fail".
set_tests_properties(integration-passphrase-wrong PROPERTIES WILL_FAIL TRUE)

# Fuzz target — uses a simple deterministic fuzzer with no libFuzzer dep.
add_executable(btc-legacy-fuzz
    src/util/sha256.cpp
    src/util/strings.cpp
    src/util/time_util.cpp
    src/util/file_util.cpp
    src/util/json_writer.cpp
    src/util/progress.cpp
    src/platform/secure_memory.cpp
    src/bdb/bdb_database.cpp
    src/bdb/bdb_reader.cpp
    src/bdb/bdb_validator.cpp
    src/bdb/bdb_writer.cpp
    src/wallet/wallet_record.cpp
    src/wallet/wallet_parser.cpp
    src/wallet/wallet_version.cpp
    src/wallet/wallet_crypto.cpp
    src/crypto/key.cpp
    src/crypto/encryption.cpp
    src/crypto/passphrase.cpp
    src/crypto/secure_memory.cpp
    src/parser/serializer.cpp
    src/recovery/recover.cpp
    src/migration/migrate.cpp
    src/cli/cli_dispatch.cpp
    src/cli/cmd_detect.cpp
    src/cli/cmd_info.cpp
    src/cli/cmd_inspect.cpp
    src/cli/cmd_validate.cpp
    src/cli/cmd_backup.cpp
    src/cli/cmd_create.cpp
    src/cli/cmd_password.cpp
    src/cli/cmd_export.cpp
    src/cli/cmd_recover.cpp
    src/cli/cmd_migrate.cpp
    src/cli/cmd_hashdump.cpp
    src/cli/cmd_version.cpp
    tests/fuzz/fuzz_main.cpp
    tests/fuzz/fuzz_bdb_parse.cpp
    tests/fuzz/fuzz_wallet_records.cpp
    tests/fuzz/fuzz_passphrase.cpp
)
target_include_directories(btc-legacy-fuzz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
btc_legacy_link_openssl(btc-legacy-fuzz)
if(NOT MSVC)
    target_link_libraries(btc-legacy-fuzz PRIVATE pthread)
endif()
