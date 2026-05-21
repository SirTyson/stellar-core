// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <vector>

#include "medida/timer.h"
#include "medida/timer_context.h"

namespace stellar
{

// Per-worker buffers used to accumulate apply-path timer samples without
// touching shared medida histograms / meters on every transaction or
// operation. The buffers are owned by the worker thread driving
// LedgerManagerImpl::applyThread and a pointer to them is published in a
// thread_local while that worker is running. When the worker finishes
// applying its cluster, all buffered samples are flushed into the
// corresponding medida timers via the batched UpdateBatch primitive, which
// acquires the histogram lock once and issues a single meter Mark per
// timer.
//
// The exact count / min / max / sum / variance accumulated by the
// histogram are preserved bit-for-bit relative to the per-sample Update
// path. The CKMS sample is also fed every sample (now under a single lock
// acquisition rather than one per sample).
struct ApplyTimerBatch
{
    std::vector<std::chrono::nanoseconds> mTxApply;
    std::vector<std::chrono::nanoseconds> mOpApply;
    std::vector<std::chrono::nanoseconds> mHostFnExec;
    std::vector<std::chrono::nanoseconds> mExtFpTtlExec;
    std::vector<std::chrono::nanoseconds> mRestoreFpExec;
};

// Returns the currently-published per-worker batch, or nullptr if the
// calling thread is not inside a parallel-apply worker scope.
ApplyTimerBatch* currentApplyTimerBatch();

// RAII guard that publishes `batch` as the current worker's batch in a
// thread_local for the lifetime of the guard, restoring the previous value
// on destruction.
class ScopedApplyTimerBatch
{
  public:
    explicit ScopedApplyTimerBatch(ApplyTimerBatch& batch);
    ~ScopedApplyTimerBatch();
    ScopedApplyTimerBatch(ScopedApplyTimerBatch const&) = delete;
    ScopedApplyTimerBatch& operator=(ScopedApplyTimerBatch const&) = delete;

  private:
    ApplyTimerBatch* mPrev;
};

// Flush a per-worker buffer into the given timer in one batched call.
// Clears the buffer on return.
void flushApplyTimerBatch(medida::Timer& timer,
                          std::vector<std::chrono::nanoseconds>& samples);

// Timer scope used on the Soroban parallel apply path. If a worker batch
// is published on this thread, the elapsed duration is appended to
// `batchBuffer` cheaply (a single steady_clock sample and a push_back) and
// no shared medida state is touched. Otherwise the scope falls back to
// the standard `timer.TimeScope()` path, preserving the previous behavior
// for any thread that isn't a parallel-apply worker.
class ApplyTimerScope
{
  public:
    // Default-construct an inactive scope (no measurement).
    ApplyTimerScope() = default;

    // Construct an active scope. If `batchBuffer` is non-null, the elapsed
    // duration will be appended to it on destruction; otherwise a
    // medida::TimerContext is held on `timer` for the lifetime of the
    // scope.
    ApplyTimerScope(medida::Timer& timer,
                    std::vector<std::chrono::nanoseconds>* batchBuffer);

    // Move-construct only (no assignment): nullifies the source so it
    // becomes a no-op on destruction. Required because some call sites
    // return `std::optional<ApplyTimerScope>` by value.
    ApplyTimerScope(ApplyTimerScope&& other) noexcept;
    ApplyTimerScope& operator=(ApplyTimerScope&&) = delete;

    ApplyTimerScope(ApplyTimerScope const&) = delete;
    ApplyTimerScope& operator=(ApplyTimerScope const&) = delete;

    ~ApplyTimerScope();

  private:
    std::vector<std::chrono::nanoseconds>* mBuffer{nullptr};
    std::optional<medida::TimerContext> mTimerCtx;
    std::chrono::steady_clock::time_point mStart;
};

} // namespace stellar
