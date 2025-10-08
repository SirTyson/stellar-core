// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/RustCrypto.h"
#include "rust/RustBridge.h"
#include <mutex>

namespace stellar
{
namespace rust_crypto
{

// Global flag protected by mutex
bool gUseRustCrypto = true;
static std::mutex gRustCryptoMutex;

void
enableRustCrypto()
{
    std::lock_guard<std::mutex> guard(gRustCryptoMutex);
    gUseRustCrypto = true;
}

void
sha256(const uint8_t* message, size_t message_len, uint8_t* output)
{
    stellar::rust_bridge::compute_sha256_rust(message, message_len, output);
}

bool
hmacSha256(const uint8_t* key, size_t key_len,
           const uint8_t* message, size_t message_len,
           uint8_t* output)
{
    return stellar::rust_bridge::compute_hmac_sha256_rust(
        key, key_len, message, message_len, output);
}

bool
hmacSha256Verify(const uint8_t* key, size_t key_len,
                 const uint8_t* message, size_t message_len,
                 const uint8_t* mac)
{
    return stellar::rust_bridge::verify_hmac_sha256_rust(
        key, key_len, message, message_len, mac);
}

}
}