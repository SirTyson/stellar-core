// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include <cstdint>
#include <cstddef>

namespace stellar
{
namespace rust_crypto
{

// Global flag to use Rust crypto implementations
// Once enabled at protocol boundary, cannot be disabled
extern bool gUseRustCrypto;

// Enable Rust crypto functions (should be called at protocol 24 boundary)
void enableRustCrypto();

// SHA-256 functions
void sha256(const uint8_t* message, size_t message_len, uint8_t* output);

// HMAC-SHA256 functions
bool hmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* message, size_t message_len,
                uint8_t* output);

bool hmacSha256Verify(const uint8_t* key, size_t key_len,
                      const uint8_t* message, size_t message_len,
                      const uint8_t* mac);

}
}