# Building btc-legacy

## Requirements

* C++20 compiler (g++ 10+, clang++ 12+, MSVC 19.29+)
* CMake 3.16+
* OpenSSL 1.1.1 or 3.x development headers
* POSIX shell (`sh`) and standard `make`

No libdb dependency — the project ships a self-contained minimal
Berkeley DB hash file reader/writer (see `src/bdb/`).

## Build (Linux x86_64)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Resulting binary: `build/btc-legacy`

## Tests

```sh
ctest --test-dir build --output-on-failure
```

## Hardened build (ASan + UBSan)

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
    -DBTC_LEGACY_ASAN=ON -DBTC_LEGACY_UBSAN=ON \
    -DBTC_LEGACY_WERROR=OFF
cmake --build build-asan -j$(nproc)
./build-asan/btc-legacy-unit-tests
./build-asan/btc-legacy-fuzz 1000
```

## Build targets

```text
btc-legacy-linux-x64
btc-legacy-linux-arm64
btc-legacy-windows-x64.exe
```

To cross-compile for ARM64 Linux:

```sh
cmake -S . -B build-arm64 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DCMAKE_SYSTEM_NAME=Linux
cmake --build build-arm64 -j$(nproc)
```

To cross-compile for Windows x64 (from Linux, using mingw-w64):

```sh
cmake -S . -B build-win -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
    -DCMAKE_SYSTEM_NAME=Windows
cmake --build build-win -j$(nproc)
```

## Install

```sh
cmake --install build
```

Default install prefix: `/usr/local`. Override with `--prefix`.

## Compiler hardening flags

The default build applies `-Wall -Wextra -Wpedantic -Wshadow
-Wconversion -Wformat=2 -Werror` (use `-DBTC_LEGACY_WERROR=OFF` to
relax to non-fatal warnings). OpenSSL's deprecated-declarations
warning is silenced **only** on the three source files that
legitimately use the legacy EC_KEY API (`src/crypto/key.cpp`,
`src/wallet/wallet_crypto.cpp`, `src/crypto/encryption.cpp`); no
global warning suppression is applied.
