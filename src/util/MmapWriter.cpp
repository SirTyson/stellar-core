// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#ifdef __linux__

#include "util/MmapWriter.h"
#include "util/Fs.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include <Tracy.hpp>
#include <fmt/format.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <random>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <system_error>
#include <unistd.h>

// Linux-specific syscall wrappers

// Define RENAME_NOREPLACE if not in headers (older glibc)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

// Only define wrapper if renameat2 not available in libc
#ifndef renameat2
#ifdef __NR_renameat2
#define SYS_RENAMEAT2 __NR_renameat2
#else
// Kernel too old / headers missing: fall back to plain rename below
#define SYS_RENAMEAT2 -1
#endif

inline int
renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
          unsigned int flags)
{
#if SYS_RENAMEAT2 != -1
    return syscall(SYS_RENAMEAT2, olddirfd, oldpath, newdirfd, newpath, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}
#endif

namespace stellar
{

MmapWriter::~MmapWriter()
{
    close();
}

MmapWriter::MmapWriter(MmapWriter&& other) noexcept
    : mFd(other.mFd)
    , mBase(other.mBase)
    , mCap(other.mCap)
    , mPos(other.mPos)
    , mTmpPath(std::move(other.mTmpPath))
    , mBytesWrittenSinceLastMsync(other.mBytesWrittenSinceLastMsync)
{
    other.mFd = -1;
    other.mBase = nullptr;
    other.mCap = 0;
    other.mPos = 0;
    other.mBytesWrittenSinceLastMsync = 0;
}

MmapWriter&
MmapWriter::operator=(MmapWriter&& other) noexcept
{
    if (this != &other)
    {
        close();
        mFd = other.mFd;
        mBase = other.mBase;
        mCap = other.mCap;
        mPos = other.mPos;
        mTmpPath = std::move(other.mTmpPath);
        mBytesWrittenSinceLastMsync = other.mBytesWrittenSinceLastMsync;

        other.mFd = -1;
        other.mBase = nullptr;
        other.mCap = 0;
        other.mPos = 0;
        other.mBytesWrittenSinceLastMsync = 0;
    }
    return *this;
}

void
MmapWriter::openInDir(std::string const& dir, std::string const& tag,
                      size_t initialCap)
{
    ZoneScoped;
    releaseAssert(!isOpen());

    // Create temp filename in bucket directory
    auto pid = getpid();
    static std::atomic<uint32_t> seq{0};

    // Retry on EEXIST (stale temp file collision)
    const int maxRetries = 10;
    for (int retry = 0; retry < maxRetries; ++retry)
    {
        if (retry > 0)
        {
            // Add random suffix on retry to avoid collision with stale files
            std::random_device rd;
            mTmpPath = std::filesystem::path(dir) /
                       fmt::format("{}.tmp.{}.{}.{}", tag, pid,
                                   seq.fetch_add(1), rd());
        }
        else
        {
            // First attempt with standard naming
            mTmpPath = std::filesystem::path(dir) /
                       fmt::format("{}.tmp.{}.{}", tag, pid, seq.fetch_add(1));
        }

        // Use O_NOFOLLOW for symlink hardening, 0640 for safer permissions
        mFd = ::open(mTmpPath.c_str(),
                     O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0640);
        if (mFd >= 0)
        {
            break; // Success
        }

        if (errno != EEXIST)
        {
            // Real error, not a collision
            throw std::system_error(
                errno, std::generic_category(),
                fmt::format("open tmp {}", mTmpPath.string()));
        }

        // EEXIST - try again with different name
        CLOG_DEBUG(Bucket, "Temp file {} exists, retrying with different name",
                   mTmpPath.string());
    }

    if (mFd < 0)
    {
        throw std::runtime_error(fmt::format(
            "Failed to create temp file after {} retries", maxRetries));
    }

    // Check if we should preallocate (optional, defaults to sparse files)
    bool preallocate = std::getenv("STELLAR_BUCKET_PREALLOCATE") != nullptr;

    if (preallocate)
    {
        // Try posix_fallocate for filesystems that support it
        if (::posix_fallocate(mFd, 0, initialCap) != 0)
        {
            // Fall back to sparse file with ftruncate
            if (::ftruncate(mFd, initialCap) != 0)
            {
                if (::close(mFd) != 0)
                {
                    // Log but continue - we're already in error path
                    CLOG_WARNING(Bucket,
                                 "close failed during error cleanup: {}",
                                 strerror(errno));
                }
                mFd = -1;
                throw std::system_error(
                    errno, std::generic_category(),
                    fmt::format("posix_fallocate {}", mTmpPath.string()));
            }
        }
    }
    else
    {
        // Default: sparse file (no preallocate)
        if (::ftruncate(mFd, initialCap) != 0)
        {
            if (::close(mFd) != 0)
            {
                // Log but continue - we're already in error path
                CLOG_WARNING(Bucket, "close failed during error cleanup: {}",
                             strerror(errno));
            }
            mFd = -1;
            throw std::system_error(
                errno, std::generic_category(),
                fmt::format("ftruncate {}", mTmpPath.string()));
        }
    }

    mCap = initialCap;
    mBase = static_cast<uint8_t*>(
        ::mmap(nullptr, mCap, PROT_READ | PROT_WRITE, MAP_SHARED, mFd, 0));
    if (mBase == MAP_FAILED)
    {
        if (::close(mFd) != 0)
        {
            // Log but continue - we're already in error path
            CLOG_WARNING(Bucket, "close failed during error cleanup: {}",
                         strerror(errno));
        }
        mFd = -1;
        throw std::system_error(errno, std::generic_category(),
                                fmt::format("mmap {}", mTmpPath.string()));
    }

    // Advise kernel for optimal memory management
    ::madvise(mBase, mCap, MADV_SEQUENTIAL); // We write sequentially
    ::madvise(mBase, mCap, MADV_DONTDUMP);   // Don't include in core dumps

    mPos = 0;
    mBytesWrittenSinceLastMsync = 0;
}

void
MmapWriter::ensureCapacity(size_t need)
{
    ZoneScoped;
    if (mPos + need <= mCap)
    {
        return;
    }

    // Use minimum growth quantum to avoid death by thousand ftruncates
    size_t growth = std::max(MIN_GROWTH_QUANTUM, mCap);
    // Pre-check for very large single writes to avoid double grow
    if (need > mCap)
    {
        growth = std::max(need, growth);
    }
    size_t newCap = std::max(mCap + growth, mPos + need);

    if (::ftruncate(mFd, newCap) != 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "ftruncate for growth");
    }

#ifdef MREMAP_MAYMOVE
    // Linux-specific mremap for efficiency
    void* newBase = ::mremap(mBase, mCap, newCap, MREMAP_MAYMOVE);
    if (newBase == MAP_FAILED)
    {
        throw std::system_error(errno, std::generic_category(), "mremap");
    }
    mBase = static_cast<uint8_t*>(newBase);
#else
    // Fall back to unmap + remap
    if (::munmap(mBase, mCap) != 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "munmap during resize");
    }
    mBase = static_cast<uint8_t*>(
        ::mmap(nullptr, newCap, PROT_READ | PROT_WRITE, MAP_SHARED, mFd, 0));
    if (mBase == MAP_FAILED)
    {
        throw std::system_error(errno, std::generic_category(),
                                "mmap after growth");
    }
#endif
    mCap = newCap;

    // Reapply madvise on new mapping
    ::madvise(mBase, mCap, MADV_SEQUENTIAL);
    ::madvise(mBase, mCap, MADV_DONTDUMP);
}

void
MmapWriter::write(const void* src, size_t n)
{
    ZoneScoped;
    releaseAssert(isOpen());
    ensureCapacity(n);
    ::memcpy(mBase + mPos, src, n);
    mPos += n;

    // Track bytes written and periodically msync for dirty page throttling
    mBytesWrittenSinceLastMsync += n;
    periodicMsyncIfNeeded();
}

void
MmapWriter::periodicMsyncIfNeeded()
{
    if (mBytesWrittenSinceLastMsync >= PERIODIC_MSYNC_BYTES)
    {
        // Async msync to trigger kernel writeback without blocking
        if (::msync(mBase, mPos, MS_ASYNC) != 0)
        {
            // Log warning but don't throw - this is a performance optimization
            CLOG_WARNING(Bucket, "msync failed during periodic sync: {}",
                         strerror(errno));
        }
        mBytesWrittenSinceLastMsync = 0;
    }
}

void
MmapWriter::finalize()
{
    ZoneScoped;
    if (mFd >= 0 && mPos < mCap)
    {
        // Correct ordering: ftruncate -> msync(MS_ASYNC) -> mprotect(PROT_READ)
        if (::ftruncate(mFd, mPos) != 0)
        {
            throw std::runtime_error("ftruncate failed: " +
                                     std::string(strerror(errno)));
        }

        // Ensure all writes are visible before marking read-only
        if (::msync(mBase, mPos, MS_ASYNC) != 0)
        {
            throw std::runtime_error("msync failed during finalize: " +
                                     std::string(strerror(errno)));
        }

        // Mark pages read-only to catch any accidental writes
        if (mBase != nullptr && mCap > 0)
        {
            if (::mprotect(mBase, mCap, PROT_READ) != 0)
            {
                // Log warning but don't throw - memory protection is defensive
                CLOG_WARNING(Bucket, "mprotect failed: {}", strerror(errno));
            }
        }
    }
}

void
MmapWriter::close()
{
    ZoneScoped;
    if (mBase != nullptr)
    {
        if (::munmap(mBase, mCap) != 0)
        {
            // Log warning but don't throw in destructor path
            CLOG_WARNING(Bucket, "munmap failed during close: {}",
                         strerror(errno));
        }
        mBase = nullptr;
    }
    if (mFd >= 0)
    {
        if (::close(mFd) != 0)
        {
            // Log warning but don't throw in destructor path
            CLOG_WARNING(Bucket, "close failed: {}", strerror(errno));
        }
        mFd = -1;
    }
}

bool
atomicRename(std::filesystem::path const& from, std::filesystem::path const& to,
             RenameDurability durability)
{
    ZoneScoped;

    if (durability == RenameDurability::Durable)
    {
        // Full durability: fsync file and directory
        fs::durableRename(from.string(), to.string(),
                          to.parent_path().string());
        return true;
    }
    else
    {
        // Non-durable: use renameat2 with RENAME_NOREPLACE if available
        int ret = ::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(),
                              RENAME_NOREPLACE);

        if (ret == 0)
        {
            // Success - make file read-only to enforce immutability
            if (::chmod(to.c_str(), 0444) != 0)
            {
                // Log warning but continue - chmod failure isn't critical
                CLOG_WARNING(Bucket, "chmod failed for {}: {}", to.string(),
                             strerror(errno));
            }
            return true;
        }

        if (errno == EEXIST)
        {
            // Target already exists - this is expected for duplicate buckets
            CLOG_DEBUG(Bucket, "Target {} already exists during rename from {}",
                       to.string(), from.string());

            // Clean up temp file
            std::error_code ec;
            std::filesystem::remove(from, ec);
            return false;
        }

        if (errno == ENOSYS)
        {
            // renameat2 not available, fall back to regular rename
            static bool loggedFallback = false;
            if (!loggedFallback)
            {
                CLOG_INFO(Bucket, "renameat2 not available, using rename()");
                loggedFallback = true;
            }

            ret = ::rename(from.c_str(), to.c_str());
            if (ret == 0)
            {
                if (::chmod(to.c_str(), 0444) != 0)
                {
                    // Log warning but continue - chmod failure isn't critical
                    CLOG_WARNING(Bucket, "chmod failed for {}: {}", to.string(),
                                 strerror(errno));
                }
                return true;
            }

            if (errno == EEXIST)
            {
                CLOG_DEBUG(Bucket,
                           "Target {} already exists during rename from {}",
                           to.string(), from.string());
                std::error_code ec;
                std::filesystem::remove(from, ec);
                return false;
            }
        }

        // Other error - this shouldn't happen for same-directory rename
        if (errno == EPERM || errno == EXDEV)
        {
            CLOG_ERROR(Bucket, "Unexpected rename error {} from {} to {}: {}",
                       errno, from.string(), to.string(), strerror(errno));
        }

        throw std::system_error(
            errno, std::generic_category(),
            fmt::format("rename {} to {}", from.string(), to.string()));
    }
}

void
cleanupStaleMmapTempFiles(std::string const& dir)
{
    ZoneScoped;

    if (!std::filesystem::exists(dir))
    {
        return;
    }

    size_t cleanedCount = 0;
    std::error_code ec;

    for (auto const& entry : std::filesystem::directory_iterator(dir, ec))
    {
        if (!entry.is_regular_file())
        {
            continue;
        }

        auto filename = entry.path().filename().string();
        // Match pattern: *.tmp.* (e.g., "top.tmp.12345.0")
        if (filename.find(".tmp.") != std::string::npos)
        {
            CLOG_DEBUG(Bucket, "Removing stale mmap temp file: {}",
                       entry.path().string());
            std::filesystem::remove(entry.path(), ec);
            if (!ec)
            {
                cleanedCount++;
            }
        }
    }

    if (cleanedCount > 0)
    {
        CLOG_INFO(Bucket, "Cleaned up {} stale mmap temp files from {}",
                  cleanedCount, dir);
    }
}

}
#endif // __linux__