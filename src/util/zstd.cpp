// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/zstd.h"

namespace stellar
{

ZstdCompressor::ZstdCompressor(int compressionLevel, int numCores)
{
    cctx = ZSTD_createCCtx();
    if (!cctx)
    {
        throw std::runtime_error("Failed to create ZSTD compression context");
    }

    ZSTD_CCtx_setParameter(cctx, ZSTD_c_nbWorkers, numCores);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, compressionLevel);
}

ZstdCompressor::~ZstdCompressor()
{
    ZSTD_freeCCtx(cctx);
}

std::vector<uint8_t>
ZstdCompressor::compress(void const* data, size_t size) const
{
    size_t const maxCompressedSize = ZSTD_compressBound(size);
    std::vector<uint8_t> compressedData(maxCompressedSize);

    size_t compressedSize = ZSTD_compress2(cctx, compressedData.data(),
                                           compressedData.size(), data, size);

    if (ZSTD_isError(compressedSize))
    {
        throw std::runtime_error(std::string("ZSTD compression error: ") +
                                 ZSTD_getErrorName(compressedSize));
    }

    compressedData.resize(compressedSize);
    return compressedData;
}

ZstdDecompressor::ZstdDecompressor(int compressionLevel)
{
    dctx = ZSTD_createDCtx();
    if (!dctx)
    {
        throw std::runtime_error("Failed to create ZSTD decompression context");
    }
}

ZstdDecompressor::~ZstdDecompressor()
{
    ZSTD_freeDCtx(dctx);
}

// TODO: Add max size check
std::vector<uint8_t>
ZstdDecompressor::decompress(void const* data, size_t size) const
{
    // Get the original size from frame header
    unsigned long long originalSize = ZSTD_getFrameContentSize(data, size);

    if (originalSize == ZSTD_CONTENTSIZE_ERROR)
    {
        throw std::runtime_error("ZSTD: Not a valid compressed buffer");
    }

    if (originalSize == ZSTD_CONTENTSIZE_UNKNOWN)
    {
        throw std::runtime_error("ZSTD: Original size unknown");
    }

    std::vector<uint8_t> decompressedData(originalSize);
    size_t decompressedSize = ZSTD_decompressDCtx(
        dctx, decompressedData.data(), decompressedData.size(), data, size);

    if (ZSTD_isError(decompressedSize))
    {
        throw std::runtime_error(std::string("ZSTD decompression error: ") +
                                 ZSTD_getErrorName(decompressedSize));
    }

    decompressedData.resize(decompressedSize);
    return decompressedData;
}

} // namespace stellar