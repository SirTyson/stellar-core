// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

// Coverage marks: a lightweight mechanism for tests to assert that specific
// internal code paths were actually executed. Inspired by the "coverage marks"
// pattern from Ferrous Systems.
//
// Usage in production code:
//     COVMARK_HIT(SOME_RARE_PATH);
//
// Usage in test code:
//     COVMARK_CHECK_HIT_IN_CURR_SCOPE(SOME_RARE_PATH);
//     // ... code that should trigger SOME_RARE_PATH ...
//
// The check-hit guard records the counter on construction and verifies it
// increased by scope exit. If the marked path was not hit, the test fails.

#include <array>
#include <atomic>
#include <cstdint>
#include <stdexcept>
#include <string>

#ifdef BUILD_TESTS
#include <fmt/format.h>
#endif

namespace stellar
{

// Each coverage mark is an enum value. Add new marks before COVMARK_COUNT.
enum CovMark : std::size_t
{
    BINARY_FUSE_POPULATE_ERROR_RETRY = 0,
    BINARY_FUSE_POPULATE_PEELING_FAILURE_RETRY,
    BINARY_FUSE_DUPLICATE_REMOVAL,

    // Bucket Index
    BUCKET_INDEX_CREATE_IN_MEMORY,
    BUCKET_INDEX_CREATE_DISK,
    BUCKET_INDEX_CACHE_SKIP_IN_MEMORY,
    BUCKET_INDEX_CACHE_ALREADY_INIT,
    BUCKET_INDEX_CACHE_DISABLED_OR_EMPTY,
    BUCKET_INDEX_CACHE_FULL,
    BUCKET_INDEX_CACHE_PARTIAL,
    BUCKET_INDEX_CACHE_HIT,
    DISK_INDEX_BLOOM_MISS,
    DISK_INDEX_KEY_FOUND,

    // BucketManager
    BUCKET_ADOPT_EXISTING,
    BUCKET_MANAGER_MERGE_REATTACH_FINISHED,
    BUCKET_MANAGER_MERGE_REATTACH_RUNNING,

    // BucketList merge decisions
    BUCKET_MERGE_WITH_EMPTY_CURR,
    BUCKET_LEVEL0_IN_MEMORY_MERGE,
    BUCKET_LEVEL0_DISK_MERGE_FALLBACK,

    // Bucket merge entry cases
    BUCKET_MERGE_DEAD_NEW_INIT,
    BUCKET_MERGE_OLD_INIT_NEW_LIVE,
    BUCKET_MERGE_OLD_INIT_NEW_DEAD,

    // BucketOutputIterator
    BUCKET_OUTPUT_EMPTY_MERGE,
    BUCKET_OUTPUT_TOMBSTONE_ELISION,

    // FutureBucket
    FUTURE_BUCKET_REATTACH_MERGE,

    // Eviction
    EVICTION_SCAN_CYCLE_RESTART,
    EVICTION_BUCKET_TOO_LARGE,

    COVMARK_COUNT // must be last
};

#ifdef BUILD_TESTS

class CovMarks
{
    std::array<std::atomic<std::uint64_t>, CovMark::COVMARK_COUNT> mCounters{};

  public:
    void
    hit(CovMark mark)
    {
        mCounters[mark].fetch_add(1, std::memory_order_relaxed);
    }

    std::uint64_t
    get(CovMark mark) const
    {
        return mCounters[mark].load(std::memory_order_relaxed);
    }

    void
    reset()
    {
        for (auto& c : mCounters)
        {
            c.store(0, std::memory_order_relaxed);
        }
    }
};

extern CovMarks gCovMarks;

class CovMarkGuard
{
    CovMark mMark;
    std::uint64_t mValueOnEntry;
    char const* mFile;
    int mLine;
    char const* mName;

  public:
    CovMarkGuard(CovMark mark, char const* file, int line, char const* name)
        : mMark(mark)
        , mValueOnEntry(gCovMarks.get(mark))
        , mFile(file)
        , mLine(line)
        , mName(name)
    {
    }

    ~CovMarkGuard() noexcept(false)
    {
        if (std::uncaught_exceptions() == 0)
        {
            auto valueOnExit = gCovMarks.get(mMark);
            if (valueOnExit <= mValueOnEntry)
            {
                throw std::runtime_error(
                    fmt::format("{}:{}: coverage mark '{}' was not hit during "
                                "this scope",
                                mFile, mLine, mName));
            }
        }
    }
};

#define COVMARK_HIT(covmark) \
    ::stellar::gCovMarks.hit(::stellar::CovMark::covmark)

#define COVMARK_CHECK_HIT_IN_CURR_SCOPE(covmark) \
    ::stellar::CovMarkGuard _covMarkGuard_##covmark( \
        ::stellar::CovMark::covmark, __FILE__, __LINE__, #covmark)

#else // !BUILD_TESTS

#define COVMARK_HIT(covmark) ((void)0)
#define COVMARK_CHECK_HIT_IN_CURR_SCOPE(covmark) ((void)0)

#endif // BUILD_TESTS
}
