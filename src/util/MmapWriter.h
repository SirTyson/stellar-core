// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#ifdef __linux__

#include "bucket/BucketUtils.h"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace stellar
{

// Linux crash-only memory-mapped file writer
//
// This class provides a crash-safe way to write files on Linux using
// mmap(MAP_SHARED). Key properties:
// - Zero blocking I/O in hot path (no fsync/msync(MS_SYNC))
// - Process crash safe when host stays up (kernel continues writeback)
// - NOT power-loss safe (requires peer recovery)
// - Atomic rename to final destination
//
// Usage pattern:
// 1. Create MmapWriter and open temp file in target directory
// 2. Write data sequentially via write()
// 3. Call finalize() to shrink file and mark read-only
// 4. Call close() to unmap and close file descriptor
// 5. Use atomicRename() to move temp file to final location
class MmapWriter
{
  public:
    MmapWriter() = default;
    ~MmapWriter();

    // Non-copyable, movable
    MmapWriter(const MmapWriter&) = delete;
    MmapWriter& operator=(const MmapWriter&) = delete;
    MmapWriter(MmapWriter&& other) noexcept;
    MmapWriter& operator=(MmapWriter&& other) noexcept;

    // Open a new temp file in the given directory with initial capacity
    void openInDir(std::string const& dir, std::string const& tag,
                   size_t initialCap);

    // Write data to the mapped region, growing as needed
    void write(const void* src, size_t n);

    // Get current write position
    size_t
    position() const
    {
        return mPos;
    }

    // Get temp file path
    std::filesystem::path const&
    tempPath() const
    {
        return mTmpPath;
    }

    // Finalize the file: shrink to actual size, msync, mark read-only
    void finalize();

    // Close the file and unmap memory
    void close();

    // Check if writer is open
    bool
    isOpen() const
    {
        return mFd >= 0;
    }

  private:
    int mFd{-1};
    uint8_t* mBase{nullptr};
    size_t mCap{0};
    size_t mPos{0};
    std::filesystem::path mTmpPath;
    size_t mBytesWrittenSinceLastMsync{0};

    // Configuration constants
    static constexpr size_t PERIODIC_MSYNC_BYTES = 64 << 20; // 64MB
    static constexpr size_t MIN_GROWTH_QUANTUM = 8 << 20;    // 8MB

    void ensureCapacity(size_t need);
    void periodicMsyncIfNeeded();
};

// Atomic rename utilities
// Note: RenameDurability is defined in bucket/BucketUtils.h

// Portable atomic rename with optional RENAME_NOREPLACE on Linux
// Returns true on success, false on EEXIST (target already exists)
// Throws on other errors
bool atomicRename(std::filesystem::path const& from,
                  std::filesystem::path const& to, RenameDurability durability);

// Clean up stale mmap temp files in directory (*.tmp.* pattern)
// Called at startup to remove files from previous crashes
void cleanupStaleMmapTempFiles(std::string const& dir);

}
#endif // __linux__