// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "NonCopyable.h"
#include "zstd/zstd.h"
#include <cstddef>
#include <vector>

namespace stellar
{

// RAII wrappers for ZSTD compression/decompression contexts
class ZstdCompressor : public NonCopyable
{
  private:
    ZSTD_CCtx* cctx;

  public:
    ZstdCompressor(int compressionLevel, int numCores);
    ~ZstdCompressor();

    // Compress data with specified parameters
    std::vector<uint8_t> compress(void const* data, size_t size) const;
};

// Compression level must be identical for both compression and decompression.
// This should be a constexpr value, but is variable for now for testing
// purposes
// Note: Decompression is always single threaded
class ZstdDecompressor : public NonCopyable
{
  private:
    ZSTD_DCtx* dctx;

  public:
    ZstdDecompressor(int compressionLevel);
    ~ZstdDecompressor();

    // Decompress data
    std::vector<uint8_t> decompress(void const* data, size_t size) const;
};

} // namespace stellar