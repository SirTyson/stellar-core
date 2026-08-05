// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/TxSetPersistor.h"

#include "crypto/Hex.h"
#include "database/Database.h"
#include "herder/Herder.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/PersistentState.h"
#include "medida/meter.h"
#include "medida/timer.h"
#include "util/Decoder.h"
#include "util/GlobalChecks.h"
#include "util/JitterInjection.h"
#include "util/Logging.h"
#include "util/MetricsRegistry.h"
#include <Tracy.hpp>
#include <xdrpp/marshal.h>

namespace stellar
{

#ifdef BUILD_TESTS
std::atomic<bool> TxSetPersistor::gForceSynchronousPersist{false};
#endif

TxSetPersistor::TxSetPersistor(Application& app)
    : mApp(app)
    , mEnabled(app.getConfig().EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST &&
               app.getDatabase().canUseMiscDB())
    , mPersistTimer(app.getMetrics().NewTimer({"herder", "txset", "persist"}))
    , mPersistWaitTimer(
          app.getMetrics().NewTimer({"herder", "txset", "persist-wait"}))
    , mFallbackMeter(app.getMetrics().NewMeter(
          {"herder", "txset", "persist-fallback"}, "txset"))
    , mDiscardMeter(app.getMetrics().NewMeter(
          {"herder", "txset", "persist-discard"}, "txset"))
{
    releaseAssert(threadIsMain());
}

TxSetPersistor::~TxSetPersistor() = default;

void
TxSetPersistor::start()
{
    releaseAssert(threadIsMain());
    if (mEnabled && !mSession)
    {
        // Application database initialization may delete and recreate the
        // SQLite files. Creating the pool before that point leaves its
        // connections attached to the unlinked, pre-initialization file.
        mSession = std::make_unique<SessionWrapper>(
            "txset-persist", mApp.getDatabase().getMiscPool());
    }
}

bool
TxSetPersistor::isEnabled() const
{
    return mEnabled;
}

void
TxSetPersistor::eraseIfCurrent(Hash const& hash, uint64_t generation)
{
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mRegistry.find(hash);
    if (it != mRegistry.end() && it->second.mGeneration == generation)
    {
        mRegistry.erase(it);
        mCond.notify_all();
    }
}

void
TxSetPersistor::runPersist(Hash const& hash, TxSetXDRFrameConstPtr frame,
                           uint64_t generation)
{
    ZoneScoped;
    try
    {
        auto persistScope = mPersistTimer.TimeScope();
        JITTER_INJECT_DELAY();

        StoredTransactionSet storedTxSet;
        frame->storeXDR(storedTxSet);
        auto encoded = decoder::encode_b64(xdr::xdr_to_opaque(storedTxSet));
        mApp.getPersistentState().persistTxSet(hash, encoded, *mSession);

        JITTER_INJECT_DELAY();
        std::lock_guard<std::mutex> lock(mMutex);
        auto it = mRegistry.find(hash);
        if (it != mRegistry.end() && it->second.mGeneration == generation)
        {
            it->second.mState = State::DONE;
            mCond.notify_all();
        }
    }
    catch (std::exception const& e)
    {
        CLOG_ERROR(Herder, "Error persisting tx set {}: {}", hexAbbrev(hash),
                   e.what());
        eraseIfCurrent(hash, generation);
    }
    catch (...)
    {
        CLOG_ERROR(Herder, "Unknown error persisting tx set {}",
                   hexAbbrev(hash));
        eraseIfCurrent(hash, generation);
    }
}

void
TxSetPersistor::runDiscard(Hash const& hash, uint64_t generation)
{
    ZoneScoped;
    try
    {
        JITTER_INJECT_DELAY();
        mApp.getPersistentState().deleteTxSets({hash}, *mSession);
    }
    catch (std::exception const& e)
    {
        // Discard is best-effort. Emission waits for this task and rechecks the
        // row, so either outcome preserves body-before-statement ordering.
        CLOG_WARNING(Herder, "Error discarding persisted tx set {}: {}",
                     hexAbbrev(hash), e.what());
    }
    catch (...)
    {
        CLOG_WARNING(Herder, "Unknown error discarding persisted tx set {}",
                     hexAbbrev(hash));
    }

    JITTER_INJECT_DELAY();
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mRegistry.find(hash);
    if (it != mRegistry.end() && it->second.mGeneration == generation)
    {
        it->second.mState = State::DISCARDED;
        mCond.notify_all();
    }
}

bool
TxSetPersistor::kickOffPersist(Hash const& hash, uint64_t slot,
                               TxSetXDRFrameConstPtr frame)
{
    releaseAssert(threadIsMain());
    releaseAssert(hash != Herder::EMPTY_TX_SET_HASH);
    releaseAssert(frame);
    if (!mEnabled || !mSession)
    {
        return false;
    }

    uint64_t generation;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto it = mRegistry.find(hash);
        if (it != mRegistry.end() &&
            (it->second.mState == State::DONE ||
             (it->second.mState == State::IN_FLIGHT &&
              it->second.mOperation == Operation::WRITE)))
        {
            return false;
        }

        generation = ++mNextGeneration;
        mRegistry.insert_or_assign(
            hash, Entry{State::IN_FLIGHT, Operation::WRITE, slot, generation});
    }

    auto task = [this, hash, frame = std::move(frame), generation]() {
        runPersist(hash, frame, generation);
    };

#ifdef BUILD_TESTS
    if (gForceSynchronousPersist.load())
    {
        task();
        return true;
    }
#endif

    if (!mApp.postOnTxSetPersistThread(std::move(task), "persist tx set"))
    {
        eraseIfCurrent(hash, generation);
        return false;
    }
    return true;
}

void
TxSetPersistor::discardPersist(Hash const& hash)
{
    releaseAssert(threadIsMain());
    if (!mEnabled || !mSession || hash == Herder::EMPTY_TX_SET_HASH)
    {
        return;
    }

    uint64_t generation;
    uint64_t slot = 0;
    {
        std::lock_guard<std::mutex> lock(mMutex);
        auto it = mRegistry.find(hash);
        // Only discard rows written by this persistor and not subsequently
        // referenced by a committed statement. NONE can mean either a
        // restored row or a DONE entry erased by noteReferenced(), and both
        // must remain present to preserve statement-implies-body ordering.
        if (it == mRegistry.end())
        {
            return;
        }

        slot = it->second.mSlot;
        if (it->second.mState == State::DISCARDED ||
            (it->second.mState == State::IN_FLIGHT &&
             it->second.mOperation == Operation::DISCARD))
        {
            return;
        }

        generation = ++mNextGeneration;
        mRegistry.insert_or_assign(
            hash,
            Entry{State::IN_FLIGHT, Operation::DISCARD, slot, generation});
    }

    auto task = [this, hash, generation]() { runDiscard(hash, generation); };
    if (!mApp.postOnTxSetPersistThread(std::move(task), "discard tx set"))
    {
        eraseIfCurrent(hash, generation);
        return;
    }
    mDiscardMeter.Mark();
}

TxSetPersistor::State
TxSetPersistor::getState(Hash const& hash) const
{
    releaseAssert(threadIsMain());
    if (!mEnabled || !mSession)
    {
        return State::NONE;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    auto it = mRegistry.find(hash);
    return it == mRegistry.end() ? State::NONE : it->second.mState;
}

void
TxSetPersistor::waitForPersists(std::unordered_set<Hash> const& hashes)
{
    releaseAssert(threadIsMain());
    if (!mEnabled || !mSession || hashes.empty())
    {
        return;
    }

    auto waitScope = mPersistWaitTimer.TimeScope();
    std::unique_lock<std::mutex> lock(mMutex);
    mCond.wait(lock, [&]() {
        for (auto const& hash : hashes)
        {
            auto it = mRegistry.find(hash);
            if (it != mRegistry.end() && it->second.mState == State::IN_FLIGHT)
            {
                return false;
            }
        }
        return true;
    });
    JITTER_INJECT_DELAY();
}

void
TxSetPersistor::noteReferenced(std::unordered_set<Hash> const& hashes)
{
    releaseAssert(threadIsMain());
    if (!mEnabled || !mSession)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    for (auto const& hash : hashes)
    {
        auto it = mRegistry.find(hash);
        if (it != mRegistry.end() && it->second.mState == State::DONE)
        {
            mRegistry.erase(it);
        }
    }
}

void
TxSetPersistor::filterGCDeleteSet(std::unordered_set<Hash>& hashesToDelete,
                                  uint64_t minSlot)
{
    releaseAssert(threadIsMain());
    if (!mEnabled || !mSession)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    for (auto it = mRegistry.begin(); it != mRegistry.end();)
    {
        auto const& entry = it->second;
        if (entry.mState == State::IN_FLIGHT ||
            (entry.mState == State::DONE && entry.mSlot >= minSlot))
        {
            hashesToDelete.erase(it->first);
            ++it;
        }
        else
        {
            // Completed discards and old, never-referenced writes no longer
            // need race protection; let this or a later GC collect them.
            it = mRegistry.erase(it);
        }
    }
}

void
TxSetPersistor::markFallback()
{
    releaseAssert(threadIsMain());
    if (mEnabled && mSession)
    {
        mFallbackMeter.Mark();
    }
}

#ifdef BUILD_TESTS
void
TxSetPersistor::drain()
{
    releaseAssert(threadIsMain());
    if (!mEnabled || !mSession)
    {
        return;
    }

    std::mutex mutex;
    std::condition_variable cond;
    bool done = false;
    bool posted = mApp.postOnTxSetPersistThread(
        [&]() {
            std::lock_guard<std::mutex> lock(mutex);
            done = true;
            cond.notify_one();
        },
        "drain tx-set persist");
    if (!posted)
    {
        return;
    }

    std::unique_lock<std::mutex> lock(mutex);
    cond.wait(lock, [&]() { return done; });
}
#endif

}
