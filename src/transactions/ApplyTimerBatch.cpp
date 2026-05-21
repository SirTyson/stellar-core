// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/ApplyTimerBatch.h"

namespace stellar
{

namespace
{
thread_local ApplyTimerBatch* tlBatch = nullptr;
}

ApplyTimerBatch*
currentApplyTimerBatch()
{
    return tlBatch;
}

ScopedApplyTimerBatch::ScopedApplyTimerBatch(ApplyTimerBatch& batch)
    : mPrev(tlBatch)
{
    tlBatch = &batch;
}

ScopedApplyTimerBatch::~ScopedApplyTimerBatch()
{
    tlBatch = mPrev;
}

void
flushApplyTimerBatch(medida::Timer& timer,
                     std::vector<std::chrono::nanoseconds>& samples)
{
    if (!samples.empty())
    {
        timer.UpdateBatch(samples.data(), samples.size());
        samples.clear();
    }
}

ApplyTimerScope::ApplyTimerScope(
    medida::Timer& timer, std::vector<std::chrono::nanoseconds>* batchBuffer)
    : mBuffer(batchBuffer)
{
    if (mBuffer)
    {
        mStart = std::chrono::steady_clock::now();
    }
    else
    {
        mTimerCtx.emplace(timer.TimeScope());
    }
}

ApplyTimerScope::ApplyTimerScope(ApplyTimerScope&& other) noexcept
    : mBuffer(other.mBuffer)
    , mTimerCtx(std::move(other.mTimerCtx))
    , mStart(other.mStart)
{
    other.mBuffer = nullptr;
    other.mTimerCtx.reset();
}

ApplyTimerScope::~ApplyTimerScope()
{
    if (mBuffer)
    {
        auto elapsed = std::chrono::steady_clock::now() - mStart;
        mBuffer->push_back(
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed));
    }
}

} // namespace stellar
