// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/TxSetFrame.h"
#include "xdr/Stellar-types.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace medida
{
class Meter;
class Timer;
}

namespace stellar
{

class Application;
class SessionWrapper;

// Serializes tx-set body persistence on a dedicated thread so it can overlap
// validation without changing body-before-statement ordering at emission.
class TxSetPersistor
{
  public:
    enum class State
    {
        NONE,
        IN_FLIGHT,
        DONE,
        DISCARDED
    };

  private:
    enum class Operation
    {
        WRITE,
        DISCARD
    };

    struct Entry
    {
        State mState;
        Operation mOperation;
        uint64_t mSlot;
        uint64_t mGeneration;
    };

    Application& mApp;
    bool const mEnabled;
    std::unique_ptr<SessionWrapper> mSession;

    mutable std::mutex mMutex;
    std::condition_variable mCond;
    std::unordered_map<Hash, Entry> mRegistry;
    uint64_t mNextGeneration{0};

    medida::Timer& mPersistTimer;
    medida::Timer& mPersistWaitTimer;
    medida::Meter& mFallbackMeter;
    medida::Meter& mDiscardMeter;

    void runPersist(Hash const& hash, TxSetXDRFrameConstPtr frame,
                    uint64_t generation);
    void runDiscard(Hash const& hash, uint64_t generation);
    void eraseIfCurrent(Hash const& hash, uint64_t generation);

  public:
    explicit TxSetPersistor(Application& app);
    ~TxSetPersistor();

    // Lease the pool session only after database initialization has completed.
    void start();
    bool isEnabled() const;

    // All public methods are main-thread-only.
    bool kickOffPersist(Hash const& hash, uint64_t slot,
                        TxSetXDRFrameConstPtr frame);
    void discardPersist(Hash const& hash);
    State getState(Hash const& hash) const;
    void waitForPersists(std::unordered_set<Hash> const& hashes);
    void noteReferenced(std::unordered_set<Hash> const& hashes);
    void filterGCDeleteSet(std::unordered_set<Hash>& hashesToDelete,
                           uint64_t minSlot);
    void markFallback();

#ifdef BUILD_TESTS
    // Tests may only change this while the persistence queue is empty. The
    // synchronous path and queued path share the single leased SQL session.
    static std::atomic<bool> gForceSynchronousPersist;
    void drain();
#endif
};

}
