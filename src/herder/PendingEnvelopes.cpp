#include "PendingEnvelopes.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "database/Database.h"
#include "herder/HerderImpl.h"
#include "herder/HerderPersistence.h"
#include "herder/HerderUtils.h"
#include "herder/TxSetFrame.h"
#include "main/Application.h"
#include "main/Config.h"
#include "overlay/RustOverlayManager.h"
#include "scp/QuorumSetUtils.h"
#include "scp/Slot.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/MetricsRegistry.h"
#include "util/UnorderedSet.h"
#include <Tracy.hpp>
#include <xdrpp/marshal.h>

using namespace std;

#define QSET_CACHE_SIZE 10000
#define TXSET_CACHE_SIZE 10000

namespace stellar
{

// Tx set fetch fallback (docs/direct-leader-flooding.md): flooding is the
// primary delivery path; a set still missing after DELAY is requested from a
// single peer, re-requested every RETRY while missing (the overlay retries a
// different peer once a request goes stale). DELAY gives the flood a
// comfortable head start; RETRY bounds the per-hash request rate to ~1/s.
std::chrono::milliseconds const TXSET_FETCH_FALLBACK_DELAY(500);
std::chrono::milliseconds const TXSET_FETCH_FALLBACK_RETRY(1000);
std::chrono::milliseconds const TXSET_FETCH_FALLBACK_TICK(250);

PendingEnvelopes::PendingEnvelopes(Application& app, HerderImpl& herder)
    : mApp(app)
    , mHerder(herder)
    , mQsetCache(QSET_CACHE_SIZE)
    , mTxSetFetchFallbackTimer(app)
    , mTxSetCache(TXSET_CACHE_SIZE)
    , mValueSizeCache(TXSET_CACHE_SIZE + QSET_CACHE_SIZE)
    , mRebuildQuorum(true)
    , mQuorumTracker(mApp.getConfig().NODE_SEED.getPublicKey())
    , mProcessedCount(
          app.getMetrics().NewCounter({"scp", "pending", "processed"}))
    , mDiscardedCount(
          app.getMetrics().NewCounter({"scp", "pending", "discarded"}))
    , mFetchingCount(
          app.getMetrics().NewCounter({"scp", "pending", "fetching"}))
    , mReadyCount(app.getMetrics().NewCounter({"scp", "pending", "ready"}))
    , mFetchDuration(app.getMetrics().NewTimer({"scp", "fetch", "envelope"}))
    , mFetchTxSetTimer(app.getMetrics().NewTimer({"overlay", "fetch", "txset"}))
    , mFetchQsetTimer(app.getMetrics().NewTimer({"overlay", "fetch", "qset"}))
    , mCostPerSlot(app.getMetrics().NewHistogram({"scp", "cost", "per-slot"}))
{
}

PendingEnvelopes::~PendingEnvelopes()
{
}

SCPQuorumSetPtr
PendingEnvelopes::getKnownQSet(Hash const& hash, bool touch)
{
    SCPQuorumSetPtr res;
    auto it = mKnownQSets.find(hash);
    if (it != mKnownQSets.end())
    {
        res = it->second.lock();
    }

    // refresh the cache for this key
    if (res && touch)
    {
        mQsetCache.put(hash, res);
    }
    return res;
}

SCPQuorumSetPtr
PendingEnvelopes::putQSet(Hash const& qSetHash, SCPQuorumSet const& qSet)
{
    CLOG_TRACE(Herder, "Add SCPQSet {}", hexAbbrev(qSetHash));
    SCPQuorumSetPtr res;
    char const* errString = nullptr;
    releaseAssert(isQuorumSetSane(qSet, false, errString));
    res = getKnownQSet(qSetHash, true);
    if (!res)
    {
        res = std::make_shared<SCPQuorumSet>(qSet);
        mKnownQSets[qSetHash] = res;
        mQsetCache.put(qSetHash, res);
    }
    return res;
}

void
PendingEnvelopes::addSCPQuorumSet(Hash const& hash, SCPQuorumSet const& q)
{
    ZoneScoped;
    putQSet(hash, q);
    mPendingQSetFetches.erase(hash);
}

bool
PendingEnvelopes::recvSCPQuorumSet(Hash const& hash, SCPQuorumSet const& q)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "Got SCPQSet {}", hexAbbrev(hash));

    // Only accept if we were actually fetching this
    if (mPendingQSetFetches.find(hash) == mPendingQSetFetches.end())
    {
        return false;
    }

    char const* errString = nullptr;
    bool res = isQuorumSetSane(q, false, errString);
    if (res)
    {
        addSCPQuorumSet(hash, q);
    }
    else
    {
        discardSCPEnvelopesWithQSet(hash);
    }
    mPendingQSetFetches.erase(hash);
    return res;
}

void
PendingEnvelopes::discardSCPEnvelopesWithQSet(Hash const& hash)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "Discarding SCP Envelopes with SCPQSet {}",
               hexAbbrev(hash));

    // Find all fetching envelopes that need this qset and discard them
    for (auto& slotEnvs : mEnvelopes)
    {
        for (auto it = slotEnvs.second.mFetchingEnvelopes.begin();
             it != slotEnvs.second.mFetchingEnvelopes.end();)
        {
            Hash qsetHash = Slot::getCompanionQuorumSetHashFromStatement(
                it->first.statement);
            if (qsetHash == hash)
            {
                discardSCPEnvelope(it->first);
                it = slotEnvs.second.mFetchingEnvelopes.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    mPendingQSetFetches.erase(hash);
}

void
PendingEnvelopes::updateMetrics()
{
    int64 processed = 0;
    int64 discarded = 0;
    int64 fetching = 0;
    int64 ready = 0;

    for (auto const& s : mEnvelopes)
    {
        auto& v = s.second;
        processed += v.mProcessedEnvelopes.size();
        discarded += v.mDiscardedEnvelopes.size();
        fetching += v.mFetchingEnvelopes.size();
        ready += v.mReadyEnvelopes.size();
    }
    TracyPlot("scp.pending.processed", processed);
    TracyPlot("scp.pending.fetching", fetching);
    mProcessedCount.set_count(processed);
    mDiscardedCount.set_count(discarded);
    mFetchingCount.set_count(fetching);
    mReadyCount.set_count(ready);
}

TxSetXDRFrameConstPtr
PendingEnvelopes::putTxSet(Hash const& hash, uint64 slot,
                           TxSetXDRFrameConstPtr txset)
{
    auto res = getKnownTxSet(hash, slot, true);
    if (!res)
    {
        res = txset;
        mKnownTxSets[hash] = res;
        mTxSetCache.put(hash, std::make_pair(slot, res));
    }
    return res;
}

// tries to find a txset in memory, setting touch also touches the LRU,
// extending the lifetime of the result *and* updating the slot number
// to a greater value if needed
TxSetXDRFrameConstPtr
PendingEnvelopes::getKnownTxSet(Hash const& hash, uint64 slot, bool touch)
{
    // slot is only used when `touch` is set
    releaseAssert(touch || (slot == 0));
    TxSetXDRFrameConstPtr res;
    auto it = mKnownTxSets.find(hash);
    if (it != mKnownTxSets.end())
    {
        res = it->second.lock();
    }

    // refresh the cache for this key
    if (res && touch)
    {
        bool update = true;
        if (mTxSetCache.exists(hash))
        {
            auto& v = mTxSetCache.get(hash);
            update = (slot > v.first);
        }
        if (update)
        {
            mTxSetCache.put(hash, std::make_pair(slot, res));
        }
    }
    return res;
}

void
PendingEnvelopes::addTxSet(Hash const& hash, uint64 lastSeenSlotIndex,
                           TxSetXDRFrameConstPtr txset)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "Add TxSet {}", hexAbbrev(hash));

    putTxSet(hash, lastSeenSlotIndex, txset);
}

bool
PendingEnvelopes::recvTxSet(Hash const& hash, TxSetXDRFrameConstPtr txset)
{
    ZoneScoped;
    CLOG_INFO(Herder, "Got TxSet {}", hexAbbrev(hash));

    // The announced hash names the set everywhere downstream (value
    // validation, externalize), while validity caches key off the computed
    // contents hash. Never store a body under a hash it does not match --
    // a mismatched entry would validate and apply a different set than the
    // one the nominated value names. (The Rust overlay derives the hash from
    // the received bytes, so a mismatch here means a bug or a hostile local
    // producer, not a network peer.)
    if (txset->getContentsHash() != hash)
    {
        CLOG_WARNING(Herder,
                     "Dropping TxSet whose contents hash {} does not match "
                     "its announced hash {}",
                     hexAbbrev(txset->getContentsHash()), hexAbbrev(hash));
        return false;
    }

    // Direct leader flooding (docs/direct-leader-flooding.md): the round-1
    // leader eagerly pushes its nominated TX set body to all peers, so it can
    // arrive BEFORE we process the nomination referencing it -- i.e. before the
    // hash is in mPendingTxSetFetches. We must therefore ACCEPT unsolicited
    // sets, not reject them: store the set so the nomination later finds it via
    // getKnownTxSet() and needs no fetch. This is exactly what lets us drop the
    // GetTxSet request round-trip -- rejecting here (the old pull-only rule)
    // would silently discard the push and, with no request fallback, wedge the
    // slot.
    //
    // Accepting unsolicited sets is a memory-DoS surface (a peer can push
    // arbitrary sets); acceptable for the experiment's authenticated dense mesh
    // and bounded by addTxSet's cache eviction. Revisit before any production
    // path (e.g. restrict to sets for slots near LCL and/or from current
    // leaders).
    addTxSet(hash, 0, txset);

    // Parallel tx set download: no longer awaiting this set. Values referencing
    // it will now validate fully (getKnownTxSet hits) on the next SCP re-drive.
    mTxSetWaiting.erase(hash);

    // Pin the set into any in-flight SCP value/envelope wrappers that were
    // created before it arrived, so it survives LRU eviction while SCP is still
    // considering those values (docs/direct-leader-flooding.md).
    mHerder.getHerderSCPDriver().onTxSetReceived(hash, txset);

    // Eager receiver-side validation (docs/direct-leader-flooding.md): a
    // round-1 leader pushes its set right after apply-finish, well before the
    // trigger fires anywhere. Build the applicable frame and prove validity
    // across the conservative close-time window now, in the pre-trigger idle
    // span, so validateValue on the referencing envelope is a cache hit --
    // and do it before replaying any parked envelopes below, which then
    // validate cheaply.
    mHerder.getHerderSCPDriver().eagerValidateTxSet(hash, txset);

    // If we were already waiting on this set (nomination processed first),
    // resume the envelopes that were blocked on it.
    auto it = mPendingTxSetFetches.find(hash);
    if (it != mPendingTxSetFetches.end())
    {
        for (auto& env : it->second)
        {
            CLOG_INFO(Herder, "Re-processing envelope after TxSet {} arrived",
                      hexAbbrev(hash));
            mApp.getHerder().recvSCPEnvelope(env);
        }
        mPendingTxSetFetches.erase(hash);
    }
    return true;
}

bool
PendingEnvelopes::isNodeDefinitelyInQuorum(NodeID const& node)
{
    if (mRebuildQuorum)
    {
        rebuildQuorumTrackerState();
        mRebuildQuorum = false;
    }
    return mQuorumTracker.isNodeDefinitelyInQuorum(node);
}

static std::string
txSetsToStr(SCPEnvelope const& envelope)
{
    auto maybeHashes = getTxSetHashes(envelope);
    if (!maybeHashes.has_value())
    {
        return "[invalid]";
    }
    auto const& hashes = maybeHashes.value();
    UnorderedSet<Hash> hashesSet(hashes.begin(), hashes.end());
    std::string res = "[";
    for (auto const& s : hashesSet)
    {
        res += hexAbbrev(s);
        res += " ";
    }
    return res + "]";
}

// called from Peer and when an Item tracker completes
Herder::EnvelopeStatus
PendingEnvelopes::recvSCPEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    auto const& nodeID = envelope.statement.nodeID;
    if (!isNodeDefinitelyInQuorum(nodeID))
    {
        CLOG_TRACE(Herder, "Dropping envelope from {} (not in quorum)",
                   mApp.getConfig().toShortString(nodeID));
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    auto const maybeValues = getStellarValues(envelope.statement);
    if (!maybeValues.has_value())
    {
        CLOG_TRACE(Herder, "Dropping envelope from {} (invalid values)",
                   mApp.getConfig().toShortString(nodeID));
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    auto const& values = maybeValues.value();
    if (std::any_of(values.begin(), values.end(), [](auto const& value) {
            // Empty-tx-set recovery values are permitted alongside signed
            // values (docs/direct-leader-flooding.md).
            return value.ext.v() != STELLAR_VALUE_SIGNED &&
                   value.ext.v() != STELLAR_VALUE_EMPTY_TX_SET;
        }))
    {
        CLOG_TRACE(Herder, "Dropping envelope from {} (value not signed)",
                   mApp.getConfig().toShortString(nodeID));
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // did we discard this envelope?
    // do we already have this envelope?
    // do we have the qset
    // do we have the txset

    try
    {
        if (isDiscarded(envelope))
        {
            CLOG_INFO(Herder,
                      "Dropping envelope from {} (previously discarded)",
                      mApp.getConfig().toShortString(nodeID));
            return Herder::ENVELOPE_STATUS_DISCARDED;
        }

        touchFetchCache(envelope);

        auto& envs = mEnvelopes[envelope.statement.slotIndex];
        auto& fetching = envs.mFetchingEnvelopes;
        auto& processed = envs.mProcessedEnvelopes;

        auto fetchIt = fetching.find(envelope);

        if (fetchIt == fetching.end())
        { // we aren't fetching this envelope
            if (processed.find(envelope) == processed.end())
            { // we haven't seen this envelope before
                // insert it into the fetching set
                fetchIt =
                    fetching.emplace(envelope, mApp.getClock().now()).first;
                startFetch(envelope);
                updateMetrics();
            }
            else
            {
                // we already have this one
                CLOG_INFO(Herder,
                          "Ignoring duplicate SCPEnvelope from {} for slot {}",
                          mApp.getConfig().toShortString(nodeID),
                          envelope.statement.slotIndex);
                return Herder::ENVELOPE_STATUS_PROCESSED;
            }
        }

        // we are fetching this envelope
        // Hand it to SCP once it is ready. Normally that means fully fetched;
        // with parallel tx set download it also means a current-ledger
        // nomination/PREPARE whose qset is present but whose tx set is still
        // arriving (isEnvelopeReady), so SCP can advance while the push lands.
        if (mHerder.getHerderSCPDriver().isEnvelopeReady(envelope))
        {
            std::chrono::nanoseconds durationNano =
                mApp.getClock().now() - fetchIt->second;
            mFetchDuration.Update(durationNano);
            Hash h = Slot::getCompanionQuorumSetHashFromStatement(
                envelope.statement);
            CLOG_TRACE(Perf,
                       "Herder fetched for envelope {} with txsets {} and "
                       "qset {} in {} seconds",
                       hexAbbrev(xdrSha256(envelope)), txSetsToStr(envelope),
                       hexAbbrev(h),
                       std::chrono::duration<double>(durationNano).count());

            // move the item from fetching to processed
            processed.emplace(envelope);
            fetching.erase(fetchIt);

            envelopeReady(envelope);
            updateMetrics();
            return Herder::ENVELOPE_STATUS_READY;
        }
        else
        {
            // else just keep waiting for it to come in
            // and refresh fetchers as needed
            startFetch(envelope);
        }

        return Herder::ENVELOPE_STATUS_FETCHING;
    }
    catch (xdr::xdr_runtime_error& e)
    {
        CLOG_TRACE(Herder,
                   "PendingEnvelopes::recvSCPEnvelope got corrupt message: {}",
                   e.what());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }
}

void
PendingEnvelopes::discardSCPEnvelope(SCPEnvelope const& envelope)
{
    try
    {
        auto& envs = mEnvelopes[envelope.statement.slotIndex];
        auto& discardedSet = envs.mDiscardedEnvelopes;
        auto r = discardedSet.insert(envelope);

        if (!r.second)
        {
            return;
        }

        envs.mFetchingEnvelopes.erase(envelope);

        stopFetch(envelope);
    }
    catch (xdr::xdr_runtime_error& e)
    {
        CLOG_TRACE(
            Herder,
            "PendingEnvelopes::discardSCPEnvelope got corrupt message: {}",
            e.what());
    }
    updateMetrics();
}

bool
PendingEnvelopes::isDiscarded(SCPEnvelope const& envelope) const
{
    auto envelopes = mEnvelopes.find(envelope.statement.slotIndex);
    if (envelopes == mEnvelopes.end())
    {
        return false;
    }

    auto& discardedSet = envelopes->second.mDiscardedEnvelopes;
    auto discarded = discardedSet.find(envelope);
    return discarded != discardedSet.end();
}

void
PendingEnvelopes::cleanKnownData()
{
    auto it = mKnownQSets.begin();
    while (it != mKnownQSets.end())
    {
        if (it->second.expired())
        {
            it = mKnownQSets.erase(it);
        }
        else
        {
            ++it;
        }
    }
    auto it2 = mKnownTxSets.begin();
    while (it2 != mKnownTxSets.end())
    {
        if (it2->second.expired())
        {
            it2 = mKnownTxSets.erase(it2);
        }
        else
        {
            ++it2;
        }
    }
}

#ifdef BUILD_TESTS
void
PendingEnvelopes::clearQSetCache()
{
    mQsetCache.clear();
    mKnownQSets.clear();
}
#endif

void
PendingEnvelopes::recordReceivedCost(SCPEnvelope const& env)
{
    ZoneScoped;

    if (!mQuorumTracker.isNodeDefinitelyInQuorum(env.statement.nodeID))
    {
        return;
    }

    // Record cost received from this validator
    size_t totalReceivedBytes = 0;
    totalReceivedBytes += xdr::xdr_argpack_size(env);

    auto const maybeValues = getStellarValues(env.statement);
    releaseAssert(maybeValues.has_value());
    for (auto const& v : maybeValues.value())
    {
        size_t txSetSize = 0;
        if (mValueSizeCache.exists(v.txSetHash))
        {
            txSetSize = mValueSizeCache.get(v.txSetHash);
        }
        else
        {
            auto txSetPtr = getTxSet(v.txSetHash);
            if (txSetPtr)
            {
                txSetSize = txSetPtr->encodedSize();
                mValueSizeCache.put(v.txSetHash, txSetSize);
            }
        }

        totalReceivedBytes += txSetSize;
    }

    auto qSetHash = Slot::getCompanionQuorumSetHashFromStatement(env.statement);
    size_t qSetSize = 0;

    if (mValueSizeCache.exists(qSetHash))
    {
        qSetSize = mValueSizeCache.get(qSetHash);
    }
    else
    {
        auto qSetPtr = getQSet(qSetHash);
        if (qSetPtr)
        {
            qSetSize = xdr::xdr_argpack_size(*qSetPtr);
            mValueSizeCache.put(qSetHash, qSetSize);
        }
    }

    totalReceivedBytes += qSetSize;

    if (totalReceivedBytes > 0)
    {
        auto const& tracked =
            mQuorumTracker.findClosestValidators(env.statement.nodeID);
        auto& cost = mEnvelopes[env.statement.slotIndex].mReceivedCost;
        for (auto& t : tracked)
        {
            cost[t] += totalReceivedBytes;
        }
    }
}

void
PendingEnvelopes::envelopeReady(SCPEnvelope const& envelope)
{
    ZoneScoped;
    auto slot = envelope.statement.slotIndex;
    CLOG_TRACE(Herder, "Envelope ready {} i:{} t:{}",
               hexAbbrev(xdrSha256(envelope)), slot,
               envelope.statement.pledges.type());

    // envelope has been fetched completely, but SCP has not done
    // any validation on values yet. Regardless, record cost of this
    // envelope.
    recordReceivedCost(envelope);

    // Do not relay an envelope received from the network. Locally emitted SCP
    // envelopes are already sent directly to every peer by HerderImpl, so
    // relaying here only amplifies duplicates in a dense topology.
    auto envW = mHerder.getHerderSCPDriver().wrapEnvelope(envelope);
    mEnvelopes[slot].mReadyEnvelopes.push_back(envW);
}

bool
PendingEnvelopes::isFullyFetched(SCPEnvelope const& envelope)
{
    if (!getKnownQSet(
            Slot::getCompanionQuorumSetHashFromStatement(envelope.statement),
            false))
    {
        return false;
    }

    auto txSetHashes = getValidatedTxSetHashes(envelope);
    return std::all_of(std::begin(txSetHashes), std::end(txSetHashes),
                       [&](Hash const& txSetHash) {
                           return getKnownTxSet(txSetHash, 0, false);
                       });
}

bool
PendingEnvelopes::isQsetFetched(SCPEnvelope const& envelope)
{
    return getKnownQSet(
               Slot::getCompanionQuorumSetHashFromStatement(envelope.statement),
               false) != nullptr;
}

bool
PendingEnvelopes::areTxSetsFetched(SCPEnvelope const& envelope)
{
    auto txSetHashes = getValidatedTxSetHashes(envelope);
    return std::all_of(std::begin(txSetHashes), std::end(txSetHashes),
                       [&](Hash const& txSetHash) {
                           return getKnownTxSet(txSetHash, 0, false) != nullptr;
                       });
}

std::optional<std::chrono::milliseconds>
PendingEnvelopes::getTxSetWaitingTime(Hash const& hash) const
{
    auto it = mTxSetWaiting.find(hash);
    if (it == mTxSetWaiting.end())
    {
        return std::nullopt;
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        mApp.getClock().now() - it->second);
}

void
PendingEnvelopes::startFetch(SCPEnvelope const& envelope)
{
    ZoneScoped;
    Hash h = Slot::getCompanionQuorumSetHashFromStatement(envelope.statement);

    // startFetch is called more than once for the same envelope (first on
    // insertion into mFetchingEnvelopes, then again on the "keep waiting" path,
    // and once per re-receipt from another peer). Dedup so a waiting envelope
    // is stored at most once per hash -- otherwise the waiting vectors (and the
    // work recvTxSet later replays) grow with every duplicate flood.
    auto addWaiter = [&](std::vector<SCPEnvelope>& vec) {
        if (std::find(vec.begin(), vec.end(), envelope) == vec.end())
        {
            vec.push_back(envelope);
        }
    };

    bool needSomething = false;
    if (!getKnownQSet(h, false))
    {
        // Track that we need this qset - will be requested via IPC
        addWaiter(mPendingQSetFetches[h]);
        needSomething = true;
    }

    for (auto const& h2 : getValidatedTxSetHashes(envelope))
    {
        auto it = mPendingTxSetFetches.find(h2);
        if (it != mPendingTxSetFetches.end())
        {
            // Already fetching - just add envelope to waiting list
            addWaiter(it->second);
        }
        else if (!getKnownTxSet(h2, 0, false))
        {
            // Track the envelope as waiting on this TX set, but do NOT request
            // it. Direct leader flooding (docs/direct-leader-flooding.md, TxSet
            // dissemination Step 5): the round-1 leader eagerly pushes the full
            // body to every peer, so on the happy path it arrives on its own
            // and resumes this envelope via addTxSet(). The GetTxSet
            // request/response round-trip is removed from the nomination
            // critical path.
            //
            // Experiment tradeoff: there is no request fallback, so if the push
            // is missed (churn/reconnect) or the slot advances to a round led
            // by a non-broadcasting node, this envelope stays pending for the
            // slot.
            auto& vec = mPendingTxSetFetches[h2];
            vec.push_back(envelope);
            // Parallel tx set download: remember when we started awaiting this
            // tx set so validateValue can treat referencing values as
            // structurally valid while the push is in flight.
            mTxSetWaiting.emplace(h2, mApp.getClock().now());
            // Arm the fetch fallback: if the flood misses us, request the set
            // rather than waiting forever (a stuck set would otherwise strand
            // this node on the slot -- flooding is push-only).
            maybeArmTxSetFetchFallbackTimer();
        }
    }

    if (needSomething)
    {
        CLOG_TRACE(Herder, "StartFetch env {} i:{} t:{}",
                   hexAbbrev(xdrSha256(envelope)), envelope.statement.slotIndex,
                   envelope.statement.pledges.type());
    }
}

void
PendingEnvelopes::maybeArmTxSetFetchFallbackTimer()
{
    if (mTxSetWaiting.empty() || mTxSetFetchFallbackArmed)
    {
        return;
    }
    mTxSetFetchFallbackArmed = true;
    mTxSetFetchFallbackTimer.expires_from_now(TXSET_FETCH_FALLBACK_TICK);
    mTxSetFetchFallbackTimer.async_wait(
        [this]() {
            mTxSetFetchFallbackArmed = false;
            txSetFetchFallbackTick();
        },
        VirtualTimer::onFailureNoop);
}

void
PendingEnvelopes::txSetFetchFallbackTick()
{
    ZoneScoped;
    auto const now = mApp.getClock().now();
    for (auto const& [hash, since] : mTxSetWaiting)
    {
        if (now - since < TXSET_FETCH_FALLBACK_DELAY)
        {
            // Give the flood its head start.
            continue;
        }
        auto it = mTxSetFetchRequested.find(hash);
        if (it != mTxSetFetchRequested.end() &&
            now - it->second < TXSET_FETCH_FALLBACK_RETRY)
        {
            // A request is in flight; the overlay dedups and, once it goes
            // stale, retries a different peer on our next request.
            continue;
        }
        CLOG_INFO(
            Herder,
            "TXSET_FETCH_FALLBACK: tx set {} still missing after {} ms; "
            "requesting from a peer (flood miss suspected)",
            hexAbbrev(hash),
            std::chrono::duration_cast<std::chrono::milliseconds>(now - since)
                .count());
        mApp.getOverlayManager().requestTxSet(hash);
        mTxSetFetchRequested[hash] = now;
    }

    // Age out waiting markers that can no longer matter: any slot resolves
    // (externalize/purge) well within this horizon, so a marker this old is
    // garbage from an abandoned slot, not an active download.
    auto const maxAge = std::chrono::minutes(5);
    for (auto it = mTxSetWaiting.begin(); it != mTxSetWaiting.end();)
    {
        if (now - it->second > maxAge)
        {
            it = mTxSetWaiting.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Drop request stamps for hashes no longer awaited (arrived or purged).
    for (auto it = mTxSetFetchRequested.begin();
         it != mTxSetFetchRequested.end();)
    {
        if (mTxSetWaiting.find(it->first) == mTxSetWaiting.end())
        {
            it = mTxSetFetchRequested.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Keep ticking while anything is still awaited.
    maybeArmTxSetFetchFallbackTimer();
}

void
PendingEnvelopes::stopFetch(SCPEnvelope const& envelope)
{
    ZoneScoped;
    Hash h = Slot::getCompanionQuorumSetHashFromStatement(envelope.statement);
    mPendingQSetFetches.erase(h);

    for (auto const& h2 : getValidatedTxSetHashes(envelope))
    {
        auto it = mPendingTxSetFetches.find(h2);
        if (it != mPendingTxSetFetches.end())
        {
            auto& vec = it->second;
            vec.erase(std::remove(vec.begin(), vec.end(), envelope), vec.end());
            if (vec.empty())
            {
                mPendingTxSetFetches.erase(it);
                // Deliberately KEEP mTxSetWaiting[h2]: early-delivered
                // envelopes are no longer in the waiter list, but the slot's
                // values still validate as structurally-valid against this
                // marker. Erasing it here turned one discarded envelope into
                // network deafness: every later statement carrying the hash
                // validated kInvalidValue and was rejected, counters stopped
                // propagating, ballot timers died (the reproduced wedge).
                // The marker is cleared on arrival (recvTxSet), on slot purge
                // (eraseOutsideRange), or by the age sweep in the fetch
                // fallback tick.
            }
        }
    }

    CLOG_TRACE(Herder, "StopFetch env {} i:{} t:{}",
               hexAbbrev(xdrSha256(envelope)), envelope.statement.slotIndex,
               envelope.statement.pledges.type());
}

void
PendingEnvelopes::touchFetchCache(SCPEnvelope const& envelope)
{
    auto qsetHash =
        Slot::getCompanionQuorumSetHashFromStatement(envelope.statement);
    getKnownQSet(qsetHash, true);

    for (auto const& h : getValidatedTxSetHashes(envelope))
    {
        getKnownTxSet(h, envelope.statement.slotIndex, true);
    }
}

SCPEnvelopeWrapperPtr
PendingEnvelopes::pop(uint64 slotIndex)
{
    auto it = mEnvelopes.begin();
    while (it != mEnvelopes.end() && slotIndex >= it->first)
    {
        auto& v = it->second.mReadyEnvelopes;
        if (v.size() != 0)
        {
            auto ret = v.back();
            v.pop_back();

            updateMetrics();
            return ret;
        }
        it++;
    }
    return nullptr;
}

vector<uint64>
PendingEnvelopes::readySlots()
{
    vector<uint64> result;
    for (auto const& entry : mEnvelopes)
    {
        if (!entry.second.mReadyEnvelopes.empty())
            result.push_back(entry.first);
    }
    return result;
}

void
PendingEnvelopes::eraseOutsideRange(std::optional<uint64> minSlot,
                                    std::optional<uint64> maxSlot,
                                    uint64 slotToKeep)
{
    stopAllOutsideRange(minSlot, maxSlot, slotToKeep);

    // Erases the envelope pointed to by `iter` if it is not for `slotToKeep`.
    // Always advances the iterator.
    auto const maybeEraseEnvelope = [&](auto& iter) {
        if (iter->first == slotToKeep)
        {
            ++iter;
        }
        else
        {
            iter = mEnvelopes.erase(iter);
        }
    };

    if (minSlot)
    {
        if (*minSlot > 0)
        {
            // report only for the highest non-future slot that we're purging
            reportCostOutliersForSlot(*minSlot - 1, true);
        }

        for (auto iter = mEnvelopes.begin(); iter != mEnvelopes.end();)
        {
            if (iter->first < *minSlot)
            {
                maybeEraseEnvelope(iter);
            }
            else
                break;
        }
    }

    if (maxSlot)
    {
        auto iter = mEnvelopes.upper_bound(*maxSlot);
        while (iter != mEnvelopes.end())
        {
            maybeEraseEnvelope(iter);
        }
    }

    // Purge tx-set fetch bookkeeping for slots outside the kept range, in step
    // with the mEnvelopes purge above. mPendingTxSetFetches holds full
    // SCPEnvelope copies and mTxSetWaiting holds a per-hash marker; both are
    // otherwise cleared only when a set actually arrives (recvTxSet) or a
    // waiter is discarded (stopFetch), so a slot whose pushed set was never
    // delivered would leak both entries forever (direct leader flooding has no
    // fetch/timeout fallback -- see startFetch).
    auto const slotPurged = [&](uint64 slot) {
        if (slot == slotToKeep)
        {
            return false;
        }
        return (minSlot && slot < *minSlot) || (maxSlot && slot > *maxSlot);
    };
    for (auto it = mPendingTxSetFetches.begin();
         it != mPendingTxSetFetches.end();)
    {
        auto& vec = it->second;
        vec.erase(std::remove_if(vec.begin(), vec.end(),
                                 [&](SCPEnvelope const& e) {
                                     return slotPurged(e.statement.slotIndex);
                                 }),
                  vec.end());
        if (vec.empty())
        {
            mTxSetWaiting.erase(it->first);
            it = mPendingTxSetFetches.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // 0 is special mark for data that we do not know the slot index
    // it is used for state loaded from database
    mTxSetCache.erase_if([&](TxSetFramCacheItem const& i) {
        if (i.first == 0 || i.first == slotToKeep)
            return false;
        return (minSlot && i.first < *minSlot) ||
               (maxSlot && i.first > *maxSlot);
    });

    cleanKnownData();
    updateMetrics();
}

void
PendingEnvelopes::stopAllOutsideRange(std::optional<uint64> minSlot,
                                      std::optional<uint64> maxSlot,
                                      uint64 slotToKeep)
{
    // Before we purge a slot, check if any envelopes are still in
    // "fetching" mode and attempt to record cost
    auto const maybeRecordCost = [&](auto const& it) {
        if (it->first == slotToKeep)
        {
            return;
        }

        auto const& envs = it->second;
        for (auto const& env : envs.mFetchingEnvelopes)
        {
            recordReceivedCost(env.first);
        }
    };

    if (minSlot)
    {
        for (auto it = mEnvelopes.begin();
             it != mEnvelopes.end() && it->first < *minSlot; it++)
        {
            maybeRecordCost(it);
        }
    }
    // Clear pending fetches for old slots - no need to track individual slots
    // since Rust overlay handles timeout/retry logic
}

void
PendingEnvelopes::forceRebuildQuorum()
{
    // force recomputing the transitive quorum
    mRebuildQuorum = true;
}

TxSetXDRFrameConstPtr
PendingEnvelopes::getTxSet(Hash const& hash)
{
    return getKnownTxSet(hash, 0, false);
}

SCPQuorumSetPtr
PendingEnvelopes::getQSet(Hash const& hash)
{
    auto qset = getKnownQSet(hash, false);
    if (qset)
    {
        return qset;
    }
    // if it was not known, see if we can find it somewhere else
    auto& scp = mHerder.getSCP();
    if (hash == scp.getLocalNode()->getQuorumSetHash())
    {
        qset = make_shared<SCPQuorumSet>(scp.getLocalQuorumSet());
    }
    else
    {
        auto& db = mApp.getDatabase();
        qset = HerderPersistence::getQuorumSet(db.getRawMiscSession(), hash);
    }
    if (qset)
    {
        qset = putQSet(hash, *qset);
    }
    return qset;
}

Json::Value
PendingEnvelopes::getJsonInfo(size_t limit)
{
    Json::Value ret;

    updateMetrics();

    auto& scp = mHerder.getSCP();
    {
        auto it = mEnvelopes.rbegin();
        size_t l = limit;
        while (it != mEnvelopes.rend() && l-- != 0)
        {
            if (it->second.mFetchingEnvelopes.size() != 0)
            {
                Json::Value& slot = ret[std::to_string(it->first)]["fetching"];
                for (auto const& kv : it->second.mFetchingEnvelopes)
                {
                    slot.append(scp.envToStr(kv.first));
                }
            }
            if (it->second.mReadyEnvelopes.size() != 0)
            {
                Json::Value& slot = ret[std::to_string(it->first)]["pending"];
                for (auto const& e : it->second.mReadyEnvelopes)
                {
                    slot.append(scp.envToStr(e->getEnvelope()));
                }
            }
            it++;
        }
    }
    return ret;
}

void
PendingEnvelopes::rebuildQuorumTrackerState()
{
    // rebuild quorum information using data sources starting with the
    // freshest source
    mQuorumTracker.rebuild([&](NodeID const& id) -> SCPQuorumSetPtr {
        SCPQuorumSetPtr res;
        if (id == mHerder.getSCP().getLocalNodeID())
        {
            res = getQSet(mHerder.getSCP().getLocalNode()->getQuorumSetHash());
        }
        else
        {
            auto m = mHerder.getSCP().getLatestMessage(id);
            if (m != nullptr)
            {
                auto h =
                    Slot::getCompanionQuorumSetHashFromStatement(m->statement);
                res = getQSet(h);
            }
            if (res == nullptr)
            {
                // see if we had some information for that node
                auto& db = mApp.getDatabase();
                auto h = HerderPersistence::getNodeQuorumSet(
                    db.getRawMiscSession(), id);
                if (h)
                {
                    res = getQSet(*h);
                }
            }
        }
        return res;
    });
}

QuorumTracker::QuorumMap const&
PendingEnvelopes::getCurrentlyTrackedQuorum() const
{
    return mQuorumTracker.getQuorum();
}

void
PendingEnvelopes::envelopeProcessed(SCPEnvelope const& env)
{
    auto const& st = env.statement;
    auto const& id = st.nodeID;

    auto h = Slot::getCompanionQuorumSetHashFromStatement(st);

    SCPQuorumSetPtr qset = getQSet(h);
    if (!mQuorumTracker.expand(id, qset))
    {
        // could not expand quorum, queue up a rebuild
        mRebuildQuorum = true;
    }
}

UnorderedMap<NodeID, size_t>
PendingEnvelopes::getCostPerValidator(uint64 slotIndex) const
{
    auto found = mEnvelopes.find(slotIndex);
    if (found != mEnvelopes.end())
    {
        return found->second.mReceivedCost;
    }
    return {};
}

static bool
shouldReportCostOutlier(double possibleOutlierCost, double expectedCost,
                        double ratioLimit)
{
    if (possibleOutlierCost <= 0 || expectedCost <= 0)
    {
        CLOG_ERROR(SCP, "Unexpected k-means value: must be positive");
        return false;
    }

    if (possibleOutlierCost / expectedCost > ratioLimit)
    {
        // If we're off by too much from the selected cluster, report the value
        return true;
    }
    return false;
}

void
PendingEnvelopes::reportCostOutliersForSlot(int64_t slotIndex,
                                            bool updateMetrics) const
{
    ZoneScoped;

    uint32_t const K_MEAN_NUM_CLUSTERS = 3;
    double const OUTLIER_COST_RATIO_LIMIT = 10;

    auto tracked = getCostPerValidator(slotIndex);
    if (tracked.empty())
    {
        return;
    }

    std::vector<double> myValidatorsTrackedCost;
    double totalCost = 0;

    for (auto const& t : tracked)
    {
        if (t.second > 0)
        {
            double cost = static_cast<double>(t.second);
            myValidatorsTrackedCost.push_back(cost);
            totalCost += cost;
        }
    }

    // Compare each node to other nodes we heard from for this slot
    // Note: do not include cost from self as it's much smaller and will
    // likely skew the data
    if (myValidatorsTrackedCost.size() > 1)
    {
        auto numClusters =
            std::min(static_cast<uint32_t>(myValidatorsTrackedCost.size()),
                     K_MEAN_NUM_CLUSTERS);
        auto clusters = k_means(myValidatorsTrackedCost, numClusters);

        if (clusters.empty() || *(clusters.begin()) <= 0)
        {
            CLOG_ERROR(SCP,
                       "Expected non-empty set of positive cluster centers");
        }
        else
        {
            Json::Value res;
            for (auto const& t : tracked)
            {
                auto clusterToCompare =
                    closest_cluster(static_cast<double>(t.second), clusters);
                auto const smallestCluster = *(clusters.begin());
                if (shouldReportCostOutlier(clusterToCompare, smallestCluster,
                                            OUTLIER_COST_RATIO_LIMIT))
                {
                    res[mApp.getConfig().toShortString(t.first)] =
                        static_cast<Json::UInt64>(t.second);
                }
            }

            Json::FastWriter fw;
            if (!res.empty())
            {
                CLOG_WARNING(SCP, "High validator costs for slot {}: {}",
                             slotIndex, fw.write(res));
            }
        }
    }

    if (updateMetrics && totalCost > 0)
    {
        mCostPerSlot.Update(static_cast<int64_t>(totalCost));
    }
}

Json::Value
PendingEnvelopes::getJsonValidatorCost(bool summary, bool fullKeys,
                                       uint64 index) const
{
    Json::Value res;

    auto computeTotalAndMaybeFillJson = [&](Json::Value& res, uint64 slot) {
        auto tracked = getCostPerValidator(slot);
        size_t total = 0;
        for (auto const& t : tracked)
        {
            if (!summary)
            {
                res[std::to_string(slot)]
                   [mApp.getConfig().toStrKey(t.first, fullKeys)] =
                       static_cast<Json::UInt64>(t.second);
            }
            total += t.second;
        }
        return total;
    };

    // Total for one or all slots
    size_t summaryTotal = 0;
    if (index == 0)
    {
        for (auto const& s : mEnvelopes)
        {
            auto slotTotal = computeTotalAndMaybeFillJson(res, s.first);
            summaryTotal += slotTotal;
        }
    }
    else
    {
        summaryTotal = computeTotalAndMaybeFillJson(res, index);
    }

    if (summary)
    {
        res = static_cast<Json::UInt64>(summaryTotal);
    }
    return res;
}
}
