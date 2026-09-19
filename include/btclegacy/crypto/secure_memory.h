// btclegacy/crypto/secure_memory.h
#pragma once
//
// Re-export of platform::secure_memory under the crypto namespace for
// convenience. The actual implementation lives in
// btclegacy::platform::SecureBuffer.
//
#include "btclegacy/platform/secure_memory.h"
namespace btclegacy::crypto {
using platform::SecureBuffer;
using platform::secure_wipe;
} // namespace btclegacy::crypto
