// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderImpl.h"

#include "bucket/BucketManager.h"
#include "crypto/Hex.h"
#include "crypto/KeyUtils.h"
#include "crypto/SHA.h"
#include "crypto/SecretKey.h"
#include "herder/FilteredEntries.h"
#include "herder/HerderPersistence.h"
#include "herder/HerderUtils.h"
#include "herder/LedgerCloseData.h"
#include "herder/QuorumIntersectionChecker.h"
#include "herder/RustQuorumCheckerAdaptor.h"
#include "herder/TxFloodValidation.h"
#include "herder/TxSetFrame.h"
#include "herder/TxSetUtils.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxnImpl.h"
#include "ledger/P23HotArchiveBug.h"
#include "lib/json/json.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/ErrorMessages.h"
#include "main/PersistentState.h"
#include "medida/counter.h"
#include "medida/meter.h"
#include "overlay/RustOverlayManager.h"
#include "process/ProcessManager.h"
#include "scp/LocalNode.h"
#include "scp/Slot.h"
#include "simulation/LoadGenerator.h"
#include "transactions/MutableTransactionResult.h"
#include "transactions/TransactionFrameBase.h"
#include "transactions/TransactionUtils.h"
#include "util/DebugMetaUtils.h"
#include "util/Decoder.h"
#include "util/LogSlowExecution.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "util/MetricsRegistry.h"
#include "util/StatusManager.h"
#include "util/Timer.h"
#include "util/XDRStream.h"
#include "xdr/Stellar-internal.h"
#include "xdrpp/marshal.h"
#include "xdrpp/types.h"
#include <Tracy.hpp>

#include "util/GlobalChecks.h"
#include <algorithm>
#include <ctime>
#include <fmt/format.h>
#include <unistd.h>

using namespace std;
namespace stellar
{

// Roughly ~10 minutes of consensus
constexpr uint32 const CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE = 120;
// 10 seconds of drift threshold
constexpr uint32 const CLOSE_TIME_DRIFT_SECONDS_THRESHOLD = 10;

std::unique_ptr<Herder>
Herder::create(Application& app)
{
    return std::make_unique<HerderImpl>(app);
}

HerderImpl::SCPMetrics::SCPMetrics(Application& app)
    : mLostSync(app.getMetrics().NewMeter({"scp", "sync", "lost"}, "sync"))
    , mEnvelopeEmit(
          app.getMetrics().NewMeter({"scp", "envelope", "emit"}, "envelope"))
    , mEnvelopeReceive(
          app.getMetrics().NewMeter({"scp", "envelope", "receive"}, "envelope"))
    , mCumulativeStatements(app.getMetrics().NewCounter(
          {"scp", "memory", "cumulative-statements"}))
    , mEnvelopeValidSig(app.getMetrics().NewMeter(
          {"scp", "envelope", "validsig"}, "envelope"))
    , mEnvelopeInvalidSig(app.getMetrics().NewMeter(
          {"scp", "envelope", "invalidsig"}, "envelope"))
    , mTriggerPrepareStartFallback(app.getMetrics().NewMeter(
          {"scp", "trigger", "prepare-start-fallback"}, "trigger"))
    , mCandidateTxSetBuild(app.getMetrics().NewMeter(
          {"scp", "txset", "candidate-build"}, "txset"))
    , mEmptyTxSetFallback(app.getMetrics().NewMeter(
          {"scp", "txset", "empty-fallback"}, "txset"))
    , mProposalPreBuilt(
          app.getMetrics().NewMeter({"scp", "prebuild", "built"}, "txset"))
    , mProposalPrePushed(
          app.getMetrics().NewMeter({"scp", "prebuild", "pushed"}, "txset"))
    , mProposalPreBuildReused(
          app.getMetrics().NewMeter({"scp", "prebuild", "reused"}, "txset"))
    , mProposalPreBuildStale(
          app.getMetrics().NewMeter({"scp", "prebuild", "stale"}, "txset"))
{
}

HerderImpl::HerderImpl(Application& app)
    : mPendingEnvelopes(app, *this)
    , mHerderSCPDriver(app, *this, mUpgrades, mPendingEnvelopes)
    , mLastSlotSaved(0)
    , mTrackingTimer(app)
    , mLastExternalize(app.getClock().now())
    , mTriggerTimer(app)
    , mOutOfSyncTimer(app)
    , mTxSetGarbageCollectTimer(app)
    , mCheckForDeadNodesTimer(app)
    , mApp(app)
    , mLedgerManager(app.getLedgerManager())
    , mSCPMetrics(app)
    , mLastQuorumMapIntersectionState(
          std::make_shared<QuorumMapIntersectionState>(app))
    , mState(Herder::HERDER_BOOTING_STATE)
{
    auto ln = getSCP().getLocalNode();

    mPendingEnvelopes.addSCPQuorumSet(ln->getQuorumSetHash(),
                                      ln->getQuorumSet());

    // Only validators can lead, so only they accumulate candidate proposals.
    mTxProposalBuilder.setEnabled(getSCP().isValidator());

    // Note: Rust overlay is now managed by RustOverlayManager
    // SCP broadcasts go through getOverlayManager().broadcastMessage()
}

HerderImpl::~HerderImpl()
{
}

Herder::State
HerderImpl::getState() const
{
    return mState;
}

uint32_t
HerderImpl::getMaxClassicTxSize() const
{
#ifdef BUILD_TESTS
    if (mMaxClassicTxSize)
    {
        return *mMaxClassicTxSize;
    }
#endif
    return MAX_CLASSIC_TX_SIZE_BYTES;
}

uint32_t
HerderImpl::getFlowControlExtraBuffer() const
{
#ifdef BUILD_TESTS
    if (mFlowControlExtraBuffer)
    {
        return *mFlowControlExtraBuffer;
    }
#endif
    return FLOW_CONTROL_BYTES_EXTRA_BUFFER;
}

void
HerderImpl::setTrackingSCPState(uint64_t index, StellarValue const& value,
                                bool isTrackingNetwork)
{
    mTrackingSCP = ConsensusData{index, value.closeTime};
    if (isTrackingNetwork)
    {
        setState(Herder::HERDER_TRACKING_NETWORK_STATE);
    }
    else
    {
        setState(Herder::HERDER_SYNCING_STATE);
    }
}

uint32
HerderImpl::trackingConsensusLedgerIndex() const
{
    releaseAssert(getState() != Herder::State::HERDER_BOOTING_STATE);
    releaseAssert(mTrackingSCP.mConsensusIndex <= UINT32_MAX);

    auto lcl = mLedgerManager.getLastClosedLedgerNum();
    if (lcl > mTrackingSCP.mConsensusIndex)
    {
        std::string msg =
            "Inconsistent state in Herder: LCL is ahead of tracking";
        CLOG_ERROR(Herder, "{}", msg);
        CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        throw std::runtime_error(msg);
    }

    return static_cast<uint32>(mTrackingSCP.mConsensusIndex);
}

TimePoint
HerderImpl::trackingConsensusCloseTime() const
{
    releaseAssert(getState() != Herder::State::HERDER_BOOTING_STATE);
    return mTrackingSCP.mConsensusCloseTime;
}

void
HerderImpl::setState(State st)
{
    bool initState = st == HERDER_BOOTING_STATE;
    if (initState && (mState == HERDER_TRACKING_NETWORK_STATE ||
                      mState == HERDER_SYNCING_STATE))
    {
        throw std::runtime_error(fmt::format(
            FMT_STRING("Invalid state transition in Herder: {} -> {}"),
            getStateHuman(mState), getStateHuman(st)));
    }
    mState = st;
}

void
HerderImpl::lostSync()
{
    mHerderSCPDriver.stateChanged();
    setState(Herder::State::HERDER_SYNCING_STATE);
}

SCP&
HerderImpl::getSCP()
{
    return mHerderSCPDriver.getSCP();
}

void
HerderImpl::syncMetrics()
{
    int64_t count = getSCP().getCumulativeStatemtCount();
    mSCPMetrics.mCumulativeStatements.set_count(count);
    TracyPlot("scp.memory.cumulative-statements", count);
}

std::string
HerderImpl::getStateHuman(State st) const
{
    static std::array<char const*, HERDER_NUM_STATE> stateStrings = {
        "HERDER_BOOTING_STATE", "HERDER_SYNCING_STATE",
        "HERDER_TRACKING_NETWORK_STATE"};
    return std::string(stateStrings[st]);
}

void
HerderImpl::bootstrap()
{
    CLOG_INFO(Herder, "Force joining SCP with local state");
    releaseAssert(getSCP().isValidator());
    releaseAssert(mApp.getConfig().FORCE_SCP);

    mLedgerManager.moveToSynced();
    mHerderSCPDriver.bootstrap();

    setupTriggerNextLedger();
    newSlotExternalized(
        mLedgerManager.getLastClosedLedgerHeader().header.scpValue);
    purgeOldSlotsAndProcessSCPQueue(true);
}

void
HerderImpl::newSlotExternalized(StellarValue const& value)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "HerderImpl::newSlotExternalized");

    // start timing next externalize from this point
    mLastExternalize = mApp.getClock().now();

    mPendingEnvelopes.forceRebuildQuorum();
}

void
HerderImpl::purgeOldSlotsAndProcessSCPQueue(bool synchronous)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "HerderImpl::purgeOldSlotsAndProcessSCPQueue");

    // perform cleanups
    // Evict slots that are outside of our ledger validity bracket
    std::optional<uint32> minSlotToRemember;
    auto minSeq = getMinLedgerSeqToRemember();
    if (minSeq > LedgerManager::GENESIS_LEDGER_SEQ)
    {
        minSlotToRemember = minSeq;
    }

    // Evict slots that are too far in the future (only meaningful when
    // tracking, as that's when we have a reliable "current" slot index)
    std::optional<uint32> maxSlotToRemember;
    if (isTracking())
    {
        maxSlotToRemember =
            nextConsensusLedgerIndex() + LEDGER_VALIDITY_BRACKET;
    }

    if (minSlotToRemember || maxSlotToRemember)
    {
        eraseOutsideRange(minSlotToRemember, maxSlotToRemember);
    }

    // Process new ready messages for the next slot when tracking.
    // When not tracking, Herder's out of sync mechanism processes all future
    // slots automatically
    processSCPQueue(synchronous);
}

void
HerderImpl::shutdown()
{
    mTrackingTimer.cancel();
    mOutOfSyncTimer.cancel();
    mTriggerTimer.cancel();
    mTxSetGarbageCollectTimer.cancel();
    mCheckForDeadNodesTimer.cancel();
}

void
HerderImpl::processExternalized(uint64 slotIndex, StellarValue const& value,
                                bool isLatestSlot)
{
    ZoneScoped;

    releaseAssert(threadIsMain());

    bool validated = getSCP().isSlotFullyValidated(slotIndex);

    CLOG_DEBUG(Herder, "HerderSCPDriver::valueExternalized index: {} txSet: {}",
               slotIndex, hexAbbrev(value.txSetHash));

    if (getSCP().isValidator() && !validated)
    {
        CLOG_WARNING(Herder,
                     "Ledger {} ({}) closed and could NOT be fully "
                     "validated by validator",
                     slotIndex, hexAbbrev(value.txSetHash));
    }

    TxSetXDRFrameConstPtr externalizedSet;
    if (value.ext.v() == STELLAR_VALUE_EMPTY_TX_SET)
    {
        // Empty-tx-set recovery (docs/direct-leader-flooding.md): the tx set
        // was dropped to break a download stall. Materialize the canonical
        // empty set for this ledger (getTxSet(EMPTY_TX_SET_HASH) is null) so
        // the ledger closes empty.
        auto const& ov = value.ext.proposedValue();
        externalizedSet = TxSetXDRFrame::makeEmpty(ov.previousLedgerHash,
                                                   ov.previousLedgerVersion);
    }
    else
    {
        externalizedSet = mPendingEnvelopes.getTxSet(value.txSetHash);
    }

    // Notify overlay to clear TXs from mempool (for RustOverlayManager)
    // Extract TX hashes from the externalized set so Rust can remove them
    std::vector<Hash> txHashes;
    if (externalizedSet)
    {
        auto txFramesList =
            externalizedSet->createTransactionFrames(mApp.getNetworkID());
        for (auto const& txPhase : txFramesList)
        {
            for (auto const& txFrame : txPhase)
            {
                txHashes.push_back(txFrame->getFullHash());
            }
        }
#ifdef BUILD_TESTS
        mApp.getLoadGenerator().cleanupAccounts(txFramesList);
#endif
    }
    // Externalized txs leave the candidate-proposal builder alongside the
    // Rust mempool.
    mTxProposalBuilder.removeTransactions(txHashes);
    mApp.getOverlayManager().notifyTxSetExternalized(value.txSetHash, txHashes);

    {
        ZoneNamedN(updateSCPHistoryZone, "update SCP history", true);
        if (slotIndex != 0)
        {
            // Save any new SCP messages received about the previous ledger.
            // NOTE: This call uses an empty `QuorumTracker::QuorumMap` because
            // there is no new quorum map for the previous ledger.
            mApp.getHerderPersistence().saveSCPHistory(
                static_cast<uint32>(slotIndex - 1),
                getSCP().getExternalizingState(slotIndex - 1),
                QuorumTracker::QuorumMap());
        }
        // Store SCP messages received about the current ledger being closed.
        mApp.getHerderPersistence().saveSCPHistory(
            static_cast<uint32>(slotIndex),
            getSCP().getExternalizingState(slotIndex),
            mPendingEnvelopes.getCurrentlyTrackedQuorum());
    }

    // reflect upgrades with the ones included in this SCP round
    {
        bool updated;
        auto newUpgrades = mUpgrades.removeUpgrades(value.upgrades.begin(),
                                                    value.upgrades.end(),
                                                    value.closeTime, updated);
        if (updated)
        {
            setUpgrades(newUpgrades);
        }
    }

    // tell the LedgerManager that this value got externalized
    // LedgerManager will perform the proper action based on its internal
    // state: apply, trigger catchup, etc
    LedgerCloseData ledgerData(static_cast<uint32_t>(slotIndex),
                               externalizedSet, value);

    // Only dump the most recent externalized tx set. Ledger sequence on a
    // written tx set shall only strictly move forward; it may have gaps with
    // the emitted debug meta, if the network is ahead of the local node
    // (assumption is that if the network is ahead of the local node, state can
    // be replayed from the archives)
    if (isLatestSlot && mApp.getConfig().METADATA_DEBUG_LEDGERS != 0)
    {
        writeDebugTxSet(ledgerData);
    }

    mLedgerManager.valueExternalized(ledgerData, isLatestSlot);
}

void
HerderImpl::writeDebugTxSet(LedgerCloseData const& lcd)
{
    ZoneScoped;

    // Dump latest externalized tx set. Do as much of error-handling as possible
    // to avoid crashing core, since this is used purely for debugging.
    auto path =
        metautils::getLatestTxSetFilePath(mApp.getConfig().BUCKET_DIR_PATH);
    try
    {
        if (fs::mkpath(path.parent_path().string()))
        {
            auto timer = LogSlowExecution(
                "write debug tx set", LogSlowExecution::Mode::AUTOMATIC_RAII,
                "took", std::chrono::milliseconds(100));
            // If we got here, then whatever previous tx set is saved has
            // already been applied, and debug meta has been emitted. Therefore,
            // it's safe to just remove it.
            std::filesystem::remove(path);
            XDROutputFileStream stream(mApp.getClock().getIOContext(),
                                       /*fsyncOnClose=*/false);
            stream.open(path.string());
            stream.writeOne(lcd.toXDR());
        }
        else
        {
            CLOG_WARNING(Ledger,
                         "Failed to make directory '{}' for debug tx set",
                         path.parent_path().string());
        }
    }
    catch (std::runtime_error& e)
    {
        CLOG_WARNING(Ledger, "Failed to dump debug tx set '{}': {}",
                     path.string(), e.what());
    }
}

static void
recordExternalizeAndCheckCloseTimeDrift(
    uint64 slotIndex, StellarValue const& value,
    std::map<uint32_t, std::pair<uint64_t, std::optional<uint64_t>>>& ctMap)
{
    auto it = ctMap.find(slotIndex);
    if (it != ctMap.end())
    {
        it->second.second = value.closeTime;
    }

    if (ctMap.size() >= CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE)
    {
        medida::Histogram h(medida::SamplingInterface::SampleType::kSliding);
        for (auto const& [ledgerSeq, closeTimePair] : ctMap)
        {
            auto const& [localCT, externalizedCT] = closeTimePair;
            if (externalizedCT)
            {
                h.Update(*externalizedCT - localCT);
            }
        }
        auto drift = static_cast<int>(h.GetSnapshot().get75thPercentile());
        if (std::abs(drift) > CLOSE_TIME_DRIFT_SECONDS_THRESHOLD)
        {
            CLOG_WARNING(Herder, POSSIBLY_BAD_LOCAL_CLOCK);
            CLOG_WARNING(Herder, "Close time local drift is: {}", drift);
        }

        ctMap.clear();
    }
}

void
HerderImpl::valueExternalized(uint64 slotIndex, StellarValue const& value,
                              bool isLatestSlot)
{
    ZoneScoped;
    int const DUMP_SCP_TIMEOUT_SECONDS = 20;

    recordExternalizeAndCheckCloseTimeDrift(slotIndex, value,
                                            mDriftCTSlidingWindow);

    if (isLatestSlot)
    {
        // called both here and at the end (this one is in case of an exception)
        trackingHeartBeat();

        // dump SCP information if this ledger took a long time
        auto gap = std::chrono::duration<double>(mApp.getClock().now() -
                                                 mLastExternalize)
                       .count();
        if (gap > DUMP_SCP_TIMEOUT_SECONDS)
        {
            auto slotInfo = getJsonQuorumInfo(getSCP().getLocalNodeID(), false,
                                              false, slotIndex);
            Json::FastWriter fw;
            CLOG_WARNING(Herder, "Ledger took {} seconds, SCP information:{}",
                         gap, fw.write(slotInfo));
        }

        // trigger will be recreated when the ledger is closed
        // we do not want it to trigger while downloading the current set
        // and there is no point in taking a position after the round is over
        mTriggerTimer.cancel();

        // This call may cause LedgerManager to trigger ledger close
        processExternalized(slotIndex, value, isLatestSlot);

        // Record externalize timing and rebuild quorum now. Purging old slots
        // and processing the SCP queue for the next slot happens later, in
        // lastClosedLedgerIncreased, once the ledger has actually closed.
        newSlotExternalized(value);

        // Check to see if quorums have changed and we need to reanalyze.
        if (mApp.getConfig().USE_QUORUM_INTERSECTION_CHECKER_V2)
        {
            // v2. performs quorum analysis in a separate process that runs the
            // Rust SAT solver.
            checkAndMaybeReanalyzeQuorumMapV2();
        }
        else
        {
            checkAndMaybeReanalyzeQuorumMap();
        }

        // heart beat *after* doing all the work (ensures that we do not include
        // the overhead of externalization in the way we track SCP)
        // Note: this only makes sense in the context of synchronous ledger
        // application on the main thread.
        if (!mApp.getConfig().parallelLedgerClose())
        {
            trackingHeartBeat();
        }
    }
    else
    {
        // This call may trigger application of buffered ledgers and in some
        // cases a ledger trigger
        processExternalized(slotIndex, value, isLatestSlot);
    }
}

void
HerderImpl::outOfSyncRecovery()
{
    ZoneScoped;

    if (isTracking())
    {
        CLOG_WARNING(Herder,
                     "HerderImpl::outOfSyncRecovery called when tracking");
        return;
    }

    // see if we can shed some data as to speed up recovery
    uint32_t maxSlotsAhead = Herder::LEDGER_VALIDITY_BRACKET;
    uint32 purgeSlot = 0;
    getSCP().processSlotsDescendingFrom(
        std::numeric_limits<uint64>::max(), [&](uint64 seq) {
            if (getSCP().gotVBlocking(seq))
            {
                if (--maxSlotsAhead == 0)
                {
                    purgeSlot = static_cast<uint32>(seq);
                }
            }
            return maxSlotsAhead != 0;
        });
    if (purgeSlot)
    {
        CLOG_INFO(Herder, "Purging slots older than {}", purgeSlot);
        // Only erase old slots. Because we're not tracking, we don't have a
        // reliable "current" slot index to use for determining which future
        // slots to keep.
        eraseOutsideRange(purgeSlot, std::nullopt);
    }
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    for (auto const& e : getSCP().getLatestMessagesSend(lcl.ledgerSeq + 1))
    {
        broadcast(e);
    }

    getMoreSCPState();
}

void
HerderImpl::broadcast(SCPEnvelope const& e)
{
    ZoneScoped;
    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        CLOG_DEBUG(Herder, "broadcast  s:{} i:{}", e.statement.pledges.type(),
                   e.statement.slotIndex);

        mSCPMetrics.mEnvelopeEmit.Mark();

        // Route through the Rust overlay via IPC (no-op in standalone mode,
        // where no overlay process runs)
        auto m = std::make_shared<StellarMessage>();
        m->type(SCP_MESSAGE);
        m->envelope() = e;
        mApp.getOverlayManager().broadcastMessage(m);
    }
}

void
HerderImpl::startOutOfSyncTimer()
{
    if (mApp.getConfig().MANUAL_CLOSE && mApp.getConfig().RUN_STANDALONE)
    {
        return;
    }

    mOutOfSyncTimer.expires_from_now(Herder::OUT_OF_SYNC_RECOVERY_TIMER);

    mOutOfSyncTimer.async_wait(
        [&]() {
            outOfSyncRecovery();
            startOutOfSyncTimer();
        },
        &VirtualTimer::onFailureNoop);
}

void
HerderImpl::emitEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    uint64 slotIndex = envelope.statement.slotIndex;

    CLOG_DEBUG(Herder, "emitEnvelope s:{} i:{} a:{}",
               envelope.statement.pledges.type(), slotIndex,
               mApp.getStateHuman());

    persistSCPState(slotIndex);

    broadcast(envelope);
}

TxSubmitStatus
HerderImpl::recvTransaction(TransactionFrameBasePtr tx, bool submittedFromSelf,
                            bool force
#ifdef BUILD_TESTS
                            ,
                            bool isLoadgenTx
#endif
)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "recv transaction {} for {}",
               hexAbbrev(tx->getFullHash()),
               KeyUtils::toShortString(tx->getSourceID()));

    bool skipValidation = force;
#ifdef BUILD_TESTS
    // Loadgen txs are locally generated and known-valid; validating them
    // would also fail in overlay-only mode where on-disk seqnums are frozen.
    skipValidation = skipValidation || isLoadgenTx;
#endif
    if (skipValidation)
    {
        // The pre-flood gate normally feeds the proposal builder; a
        // validation-skipping submission must feed it directly or the tx is
        // never proposable by this node.
        mTxProposalBuilder.addTransaction(tx);
        auto const& env = tx->getEnvelope();
        mApp.getOverlayManager().broadcastTransaction(env, tx->getFullFee(),
                                                      tx->getNumOperations());
        return TxSubmitStatus::TX_STATUS_PENDING;
    }

    // Pre-flood validation gate: run the overlay validity checks on the
    // tx-validation pool and only hand the tx to the overlay if they pass.
    // The overlay IPC submit is mutex-guarded, so the callback can invoke it
    // directly from the pool thread.
    auto envelopes = std::make_shared<std::vector<TransactionEnvelope>>(
        1, tx->getEnvelope());
    int64_t fullFee = tx->getFullFee();
    uint32_t numOps = tx->getNumOperations();
    Hash fullHash = tx->getFullHash();
    validateTxBatchForFlooding(
        mApp, envelopes,
        [this, envelopes, fullFee, numOps,
         fullHash](TxFloodVerdicts const& verdicts) {
            if (verdicts.size() == 1 && verdicts[0])
            {
                mApp.getOverlayManager().broadcastTransaction((*envelopes)[0],
                                                              fullFee, numOps);
            }
            else
            {
                CLOG_DEBUG(Herder,
                           "Dropping submitted tx {} that failed pre-flood "
                           "validation",
                           hexAbbrev(fullHash));
            }
        });
    return TxSubmitStatus::TX_STATUS_PENDING;
}

bool
HerderImpl::checkCloseTime(SCPEnvelope const& envelope, bool enforceRecent)
{
    ZoneScoped;
    using std::placeholders::_1;
    auto const& st = envelope.statement;

    uint64_t ctCutoff = 0;

    if (enforceRecent)
    {
        auto now = VirtualClock::to_time_t(mApp.getClock().system_now());
        if (now >= mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT)
        {
            ctCutoff = now - mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT;
        }
    }

    auto envLedgerIndex = envelope.statement.slotIndex;
    auto& scpD = getHerderSCPDriver();

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    auto lastCloseIndex = lcl.ledgerSeq;
    auto lastCloseTime = lcl.scpValue.closeTime;

    // see if we can get a better estimate of lastCloseTime for validating this
    // statement using consensus data:
    // update lastCloseIndex/lastCloseTime to be the highest possible but still
    // be less than envLedgerIndex
    if (getState() != HERDER_BOOTING_STATE)
    {
        auto trackingIndex = trackingConsensusLedgerIndex();
        if (envLedgerIndex >= trackingIndex && trackingIndex > lastCloseIndex)
        {
            lastCloseIndex = static_cast<uint32>(trackingIndex);
            lastCloseTime = trackingConsensusCloseTime();
        }
    }

    StellarValue sv;
    // performs the most conservative check:
    // returns true if one of the values is valid
    auto checkCTHelper = [&](std::vector<Value> const& values) {
        return std::any_of(values.begin(), values.end(), [&](Value const& e) {
            auto r = toStellarValue(e, sv);
            // sv must be after cutoff
            r = r && sv.closeTime >= ctCutoff;
            if (r)
            {
                // statement received after the fact, only keep externalized
                // value
                r = (lastCloseIndex == envLedgerIndex &&
                     lastCloseTime == sv.closeTime);
                // for older messages, just ensure that they occurred before
                r = r || (lastCloseIndex > envLedgerIndex &&
                          lastCloseTime > sv.closeTime);
                // for future message, perform the same validity check than
                // within SCP
                r = r || scpD.checkCloseTime(envLedgerIndex, lastCloseTime, sv);
            }
            return r;
        });
    };

    bool b;

    switch (st.pledges.type())
    {
    case SCP_ST_NOMINATE:
        b = checkCTHelper(st.pledges.nominate().accepted) ||
            checkCTHelper(st.pledges.nominate().votes);
        break;
    case SCP_ST_PREPARE:
    {
        auto& prep = st.pledges.prepare();
        b = checkCTHelper({prep.ballot.value});
        if (!b && prep.prepared)
        {
            b = checkCTHelper({prep.prepared->value});
        }
        if (!b && prep.preparedPrime)
        {
            b = checkCTHelper({prep.preparedPrime->value});
        }
    }
    break;
    case SCP_ST_CONFIRM:
        b = checkCTHelper({st.pledges.confirm().ballot.value});
        break;
    case SCP_ST_EXTERNALIZE:
        b = checkCTHelper({st.pledges.externalize().commit.value});
        break;
    default:
        abort();
    }

    if (!b)
    {
        CLOG_TRACE(Herder, "Invalid close time processing {}",
                   getSCP().envToStr(st));
    }
    return b;
}

uint32_t
HerderImpl::getMinLedgerSeqToRemember() const
{
    auto maxSlotsToRemember = mApp.getConfig().MAX_SLOTS_TO_REMEMBER;
    auto currSlot = trackingConsensusLedgerIndex();
    if (currSlot > maxSlotsToRemember)
    {
        return (currSlot - maxSlotsToRemember + 1);
    }
    else
    {
        return LedgerManager::GENESIS_LEDGER_SEQ;
    }
}

Herder::EnvelopeStatus
HerderImpl::recvSCPEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    mSCPMetrics.mEnvelopeReceive.Mark();

    // **** first perform checks that do NOT require signature verification
    // this allows to fast fail messages that we'd throw away anyways

    uint32_t minLedgerSeq = getMinLedgerSeqToRemember();
    uint32_t maxLedgerSeq = std::numeric_limits<uint32>::max();

    if (!checkCloseTime(envelope, false))
    {
        // if the envelope contains an invalid close time, don't bother
        // processing it as we're not going to forward it anyways and it's
        // going to just sit in our SCP state not contributing anything useful.
        CLOG_TRACE(
            Herder,
            "skipping invalid close time (incompatible with current state)");
        std::string txt("DISCARDED - incompatible close time");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    auto checkpoint = getMostRecentCheckpointSeq();
    auto index = envelope.statement.slotIndex;

    if (isTracking())
    {
        // when tracking, we can filter messages based on the information we got
        // from consensus for the max ledger

        // note that this filtering will cause a node on startup
        // to potentially drop messages outside of the bracket
        // causing it to discard CONSENSUS_STUCK_TIMEOUT_SECONDS worth of
        // ledger closing
        maxLedgerSeq = nextConsensusLedgerIndex() + LEDGER_VALIDITY_BRACKET;
    }
    // Allow message with a drift larger than MAXIMUM_LEDGER_CLOSETIME_DRIFT if
    // it is a checkpoint message. When validator joining from genesis is needed
    // to unstick the network, ignore close time that is too old in order to
    // advance consensus (this usually applies to test networks).
    else if (!checkCloseTime(envelope,
                             trackingConsensusLedgerIndex() <=
                                     LedgerManager::GENESIS_LEDGER_SEQ &&
                                 index != nextConsensusLedgerIndex()) &&
             index != checkpoint)
    {
        // if we've never been in sync, we can be more aggressive in how we
        // filter messages: we can ignore messages that are unlikely to be
        // the latest messages from the network
        CLOG_TRACE(Herder, "recvSCPEnvelope: skipping invalid close time "
                           "(check MAXIMUM_LEDGER_CLOSETIME_DRIFT)");
        std::string txt("DISCARDED - invalid close time");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // If envelopes are out of our validity brackets, or if envelope does not
    // contain the checkpoint for early catchup, we just ignore them.
    if ((index > maxLedgerSeq || index < minLedgerSeq) && index != checkpoint)
    {
        CLOG_TRACE(Herder, "Ignoring SCPEnvelope outside of range: {}( {},{})",
                   envelope.statement.slotIndex, minLedgerSeq, maxLedgerSeq);
        std::string txt("DISCARDED - out of range");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // **** from this point, we have to check signatures
    if (!verifyEnvelope(envelope))
    {
        std::string txt("DISCARDED - bad envelope");
        ZoneText(txt.c_str(), txt.size());
        CLOG_TRACE(Herder, "Received bad envelope, discarding");
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (envelope.statement.nodeID == getSCP().getLocalNode()->getNodeID())
    {
        CLOG_TRACE(Herder, "recvSCPEnvelope: skipping own message");
        std::string txt("SKIPPED_SELF");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_SKIPPED_SELF;
    }

    auto status = mPendingEnvelopes.recvSCPEnvelope(envelope);
    if (status == Herder::ENVELOPE_STATUS_READY)
    {
        std::string txt("READY");
        ZoneText(txt.c_str(), txt.size());
        CLOG_DEBUG(Herder, "recvSCPEnvelope (ready) from: {} s:{} i:{} a:{}",
                   mApp.getConfig().toShortString(envelope.statement.nodeID),
                   envelope.statement.pledges.type(),
                   envelope.statement.slotIndex, mApp.getStateHuman());

        processSCPQueue(true);
    }
    else
    {
        if (status == Herder::ENVELOPE_STATUS_FETCHING)
        {
            std::string txt("FETCHING");
            ZoneText(txt.c_str(), txt.size());
        }
        else if (status == Herder::ENVELOPE_STATUS_PROCESSED)
        {
            std::string txt("PROCESSED");
            ZoneText(txt.c_str(), txt.size());
        }
        CLOG_TRACE(Herder, "recvSCPEnvelope ({}) from: {} s:{} i:{} a:{}",
                   static_cast<int>(status),
                   mApp.getConfig().toShortString(envelope.statement.nodeID),
                   envelope.statement.pledges.type(),
                   envelope.statement.slotIndex, mApp.getStateHuman());
    }
    return status;
}

#ifdef BUILD_TESTS

Herder::EnvelopeStatus
HerderImpl::recvSCPEnvelope(SCPEnvelope const& envelope,
                            const SCPQuorumSet& qset,
                            TxSetXDRFrameConstPtr txset)
{
    ZoneScoped;
    mPendingEnvelopes.addTxSet(txset->getContentsHash(),
                               envelope.statement.slotIndex, txset);
    mPendingEnvelopes.addSCPQuorumSet(xdrSha256(qset), qset);
    return recvSCPEnvelope(envelope);
}

Herder::EnvelopeStatus
HerderImpl::recvSCPEnvelope(SCPEnvelope const& envelope,
                            SCPQuorumSet const& qset,
                            StellarMessage const& txset)
{
    auto txSetFrame =
        txset.type() == TX_SET
            ? TxSetXDRFrame::makeFromWire(txset.txSet())
            : TxSetXDRFrame::makeFromWire(txset.generalizedTxSet());
    return recvSCPEnvelope(envelope, qset, txSetFrame);
}

void
HerderImpl::externalizeValue(TxSetXDRFrameConstPtr txSet, uint32_t ledgerSeq,
                             uint64_t closeTime,
                             xdr::xvector<UpgradeType, 6> const& upgrades,
                             std::optional<SecretKey> skToSignValue)
{
    getPendingEnvelopes().putTxSet(txSet->getContentsHash(), ledgerSeq, txSet);
    auto sk = skToSignValue ? *skToSignValue : mApp.getConfig().NODE_SEED;
    StellarValue sv =
        makeStellarValue(txSet->getContentsHash(), closeTime, upgrades, sk);
    getHerderSCPDriver().valueExternalized(ledgerSeq, xdr::xdr_to_opaque(sv));
    while (mApp.getLedgerManager().getLastClosedLedgerNum() < ledgerSeq)
    {
        mApp.getClock().crank(true);
    }
}

#endif

std::vector<SCPEnvelope>
HerderImpl::getSCPStateForPeer(uint32 ledgerSeq)
{
    ZoneScoped;
    std::vector<SCPEnvelope> envelopes;
    auto maxSlots = Herder::LEDGER_VALIDITY_BRACKET;

    // Collect up to MAX_SLOTS_TO_SEND slots worth of envelopes
    getSCP().processSlotsAscendingFrom(ledgerSeq, [&](uint64 seq) {
        bool slotHadData = false;
        getSCP().processCurrentState(
            seq,
            [&](SCPEnvelope const& e) {
                envelopes.push_back(e);
                slotHadData = true;
                return true; // continue
            },
            false);
        if (slotHadData)
        {
            --maxSlots;
        }
        return maxSlots != 0;
    });

    return envelopes;
}

void
HerderImpl::processSCPQueue(bool synchronous)
{
    ZoneScoped;
    if (isTracking())
    {
        ZoneScoped;
        std::string txt("tracking");
        ZoneText(txt.c_str(), txt.size());

        // process any statements up to the next slot
        // this may cause it to externalize
        auto nextIndex = nextConsensusLedgerIndex();
        if (mApp.getLedgerManager().isApplying())
        {
            nextIndex =
                std::min(nextIndex,
                         mApp.getLedgerManager().getLastClosedLedgerNum() + 1);
        }
        auto processSCPQueueSomeMore = [this, nextIndex] {
            if (mApp.isStopping())
            {
                return;
            }
            processSCPQueueUpToIndex(nextIndex);
        };

        if (synchronous)
        {
            processSCPQueueSomeMore();
        }
        else
        {
            mApp.postOnMainThread(processSCPQueueSomeMore,
                                  "processSCPQueueSomeMore");
        }
    }
    else
    {
        std::string txt("not tracking");
        ZoneText(txt.c_str(), txt.size());
        // we don't know which ledger we're in
        // try to consume the messages from the queue
        // starting from the smallest slot
        for (auto& slot : mPendingEnvelopes.readySlots())
        {
            processSCPQueueUpToIndex(slot);
            if (isTracking())
            {
                // one of the slots externalized
                // we go back to regular flow
                break;
            }
        }
    }
}

void
HerderImpl::processSCPQueueUpToIndex(uint64 slotIndex)
{
    ZoneScoped;
    while (true)
    {
        SCPEnvelopeWrapperPtr envW = mPendingEnvelopes.pop(slotIndex);
        if (envW)
        {
            auto r = getSCP().receiveEnvelope(envW);
            if (r == SCP::EnvelopeState::VALID)
            {
                auto const& env = envW->getEnvelope();
                auto const& st = env.statement;
                if (st.pledges.type() == SCP_ST_EXTERNALIZE)
                {
                    mHerderSCPDriver.recordSCPExternalizeEvent(
                        st.slotIndex, st.nodeID, false);
                }
                mPendingEnvelopes.envelopeProcessed(env);
            }
        }
        else
        {
            return;
        }
    }
}

#ifdef BUILD_TESTS
PendingEnvelopes&
HerderImpl::getPendingEnvelopes()
{
    return mPendingEnvelopes;
}

Upgrades const&
HerderImpl::getUpgrades() const
{
    return mUpgrades;
}
#endif

std::chrono::milliseconds
HerderImpl::ctValidityOffset(uint64_t ct, std::chrono::milliseconds maxCtOffset)
{
    auto maxCandidateCt = mApp.getClock().system_now() + maxCtOffset +
                          Herder::MAX_TIME_SLIP_SECONDS;
    auto minCandidateCt = VirtualClock::from_time_t(ct);

    if (minCandidateCt > maxCandidateCt)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   minCandidateCt - maxCandidateCt) +
               std::chrono::milliseconds(1);
    }

    return std::chrono::milliseconds::zero();
}

void
HerderImpl::lastClosedLedgerIncreased(bool latest, TxSetXDRFrameConstPtr txSet,
                                      bool upgradeApplied)
{
    releaseAssert(threadIsMain());

    // Ensure potential upgrades are handled in overlay
    maybeHandleUpgrade();

    // If we're in sync and there are no buffered ledgers to apply, trigger next
    // ledger
    if (latest)
    {
        // Re-start heartbeat tracking _after_ applying the most up-to-date
        // ledger. This guarantees out-of-sync timer won't fire while we have
        // ledgers to apply (applicable during parallel ledger apply).
        trackingHeartBeat();

        // Ensure out of sync recovery did not get triggered while we were
        // applying
        releaseAssert(isTracking());
        releaseAssert(trackingConsensusLedgerIndex() ==
                      mLedgerManager.getLastClosedLedgerNum());
        releaseAssert(mLedgerManager.isSynced());

        // TX sets that arrived while this ledger was applying can now be
        // eagerly validated against the settled LCL, ahead of the trigger
        // and of any envelope referencing them.
        mHerderSCPDriver.drainPendingEagerValidation();

        setupTriggerNextLedger();

        // The just-closed ledger's hash seeds leader election for slot L+2
        // (N-2 pipelining); push the newly-computable leaders to the overlay.
        pushLeaderSchedule();

        // Refresh the proposal builder's capacity against the (possibly
        // upgraded) ledger limits and sweep out aged-out candidates.
        mTxProposalBuilder.setCapacityAndSweep(std::max<size_t>(
            1000, 2 * mLedgerManager.getLastMaxTxSetSizeOps()));

        // Now that the new ledger is closed, purge SCP slots outside of our
        // validity bracket and process any already-buffered SCP envelopes for
        // the next slot. Posted to the main thread so control returns to the
        // caller first, matching the previous post-externalize behavior.
        purgeOldSlotsAndProcessSCPQueue(false);

        // If we lead the next slot's round 1, pre-build the proposal and
        // eagerly push it now, filling the idle window until the trigger
        // timer; nomination itself still waits for the trigger (cadence is
        // unchanged). MUST run after purgeOldSlotsAndProcessSCPQueue -- that
        // is what sends LEDGER_CLOSED(N-1), and a BROADCAST_TX_SET ordered
        // before it would race the overlay's slot bookkeeping -- and after
        // pushLeaderSchedule, so post-freeze tx arrivals flood to the next
        // slot's leaders rather than this frozen proposal.
        maybePreBuildProposal();
    }
}

void
HerderImpl::pushLeaderSchedule()
{
    releaseAssert(threadIsMain());
    if (!getSCP().isValidator())
    {
        return;
    }

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

    // Cross-node agreement on the pushed schedule requires node weights that
    // ignore isLocalNode (as the application-specific election's do). The
    // old-style election boosts the local node, so under it every validator
    // pushes a different, self-biased target set and "flood to the leader"
    // degrades to "flood to a per-node guess" (INV fallback still covers
    // liveness). Warn once so operators can tell which regime they are in.
    if (!mWarnedOldStyleLeaderSchedule &&
        (protocolVersionIsBefore(
             lcl.header.ledgerVersion,
             APPLICATION_SPECIFIC_NOMINATION_LEADER_ELECTION_PROTOCOL_VERSION) ||
         !mApp.getConfig().VALIDATOR_WEIGHT_CONFIG.has_value() ||
         mApp.getConfig().FORCE_OLD_STYLE_LEADER_ELECTION))
    {
        mWarnedOldStyleLeaderSchedule = true;
        CLOG_WARNING(
            Herder,
            "Direct leader flooding: old-style (self-biased) leader election "
            "weights are active, so the pushed leader schedule differs per "
            "node; targeted flooding will be approximate");
    }
    uint64_t const slotIndex = lcl.header.ledgerSeq + 2;
    auto leaders = mHerderSCPDriver.computeLeaderSchedule(
        lcl.hash, slotIndex, mApp.getConfig().FLOOD_LEADER_COUNT);

    std::vector<std::string> strkeys;
    strkeys.reserve(leaders.size());
    for (auto const& id : leaders)
    {
        strkeys.emplace_back(KeyUtils::toStrKey(id));
    }
    mApp.getOverlayManager().getOverlayIPC().updateLeaders(slotIndex, strkeys);
}

VirtualClock::time_point
HerderImpl::triggerAnchorFromPrepareStart(
    uint64_t lastIndex, VirtualClock::time_point now,
    std::chrono::milliseconds expectedClose)
{
    auto lastStart = mHerderSCPDriver.getPrepareStart(lastIndex);
    if (lastStart)
    {
        return *lastStart;
    }
    // Pessimistic estimate: assume the previous ballot protocol started one
    // full interval ago, so the next trigger should fire immediately.
    return now - expectedClose;
}

// Compute the anchor for the next trigger. Caller fires at
// `anchor + expectedClose`. Unlike the local ballot cadence trigger, this uses
// the externalized close time from the previous ledger, which is a timestamp
// coming from a different node whose system clock may be drifted relative to
// ours. This is more accurate than just using local timers, as those skew late
// based on latency from the leader, but we need to be careful to account for
// drift.
//
// Constraints:
// 1. Track `expectedClose` on the network timeline as closely as possible.
// 2. Under drift, prefer a longer ledger to a shorter one to prevent fast
//    ledgers causing too much strain on the network.
// 3. Never let a badly lagging local clock wedge the node (i.e. never schedule
//    a trigger in the far future).
//
// Scenarios (assume last `closeTime` = N, target = 5s):
// 1. Our clock ahead of network: Check how much time our system clock says has
//    elapsed since the externalized network ledger closed
//    (timeSinceNetworkLedgerStart). If timeSinceNetworkLedgerStart > target,
//    either the network itself is slow, or our clock is ahead.
//
//   To get a better sense of which, we also take into account
//   nomination time, so the check becomes timeSinceNetworkLedgerStart > target
//   + nominationBudget, where nomination budget scales with timeouts.
//
//   If we think we're drifting ahead after taking nomination into account, we
//   fall back to prepare-start anchor, which is based on our local clock and
//   can't drift, but is slower.
//
//   Note that if nomination is quick, but apply takes a long time, it still
//   appears like we're ahead and we fall back to prepare-start. This isn't a
//   problem. The prepare-start timer starts before the apply stage, so a long
//   apply is "baked in" to the time. If apply was the bottleneck, we'll
//   probably trigger immediately even if we use the prepare-start timer because
//   we're behind, so using prepare-start is identical to the network-based
//   anchor from the perf standpoint if we really are in sync anyway.
//
//   This is not true for nomination. The prepare-start timer starts after
//   nomination, so it does not reflect a long nomination. This is why we need
//   the nomination budget in our check. If nomination took a long time and we
//   fall back to the conservative timer, this is much worse from a perf
//   perspective, as we are waiting nomination time + target time before
//   starting the next ledger.
//
// 2. Our clock behind network: Check whether our local timer says
//    more time has elapsed since prepare-start vs how much time has
//    elapsed since the externalized network ledger closed.
//
//   If true, our system clock is lagging far enough that the network-based
//   anchor would schedule the next trigger later than the conservative timer
//   based on local ballot cadence. That delay can grow with drift and wedge the
//   node if arbitrarily in the future, so we fall back to the prepare-start
//   anchor. This anchor is conservative and local, but it gives us a bounded
//   trigger time even when system time is badly behind.
//
// 3. Clocks synced, but nomination/apply was slow: With synced clocks,
//    time since network close time is large because real time really passed,
//    not because our system clock drifted. The goal is to avoid falling back to
//    a conservative timer and snowballing the real delay.
//
//    See scenario 1, but TL;DR we can look at the nomination timeouts and see
//    if the network is slow vs. the node drifting. If nomination is slow, we
//    can't fall back to the prepare-apply timer because it would compound the
//    delay. If apply is slow, it doesn't matter which timer we use, they both
//    will result in triggering immediately.
VirtualClock::time_point
HerderImpl::triggerAnchorFromConsensusCloseTime(
    uint64_t lastIndex, VirtualClock::time_point now,
    std::chrono::milliseconds expectedClose)
{
    auto fallbackToPrepareStart = [&]() {
        mSCPMetrics.mTriggerPrepareStartFallback.Mark();
        return triggerAnchorFromPrepareStart(lastIndex, now, expectedClose);
    };

    auto consensusCloseTime = trackingConsensusCloseTime();
    if (consensusCloseTime == 0)
    {
        CLOG_WARNING(Herder, "Consensus close time is 0, falling back to "
                             "prepare-start anchor");
        return fallbackToPrepareStart();
    }

    // Compare elapsed time on the externalized closeTime timeline with elapsed
    // time on our local prepare-start timeline.
    // Relation, with drift > 0 meaning our clock is ahead of network time:
    //
    //   timeSinceNetworkLedgerStart
    //     = nominationBudget + timeSinceLocalBallotStart + drift
    //
    // where nominationBudget is the slow-nomination allowance described above.
    auto externalizedSystemTime = VirtualClock::from_time_t(consensusCloseTime);
    auto currentSystemTime = mApp.getClock().system_now();
    auto timeSinceNetworkLedgerStart =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            currentSystemTime - externalizedSystemTime);

    auto localBallotStart =
        triggerAnchorFromPrepareStart(lastIndex, now, expectedClose);
    auto timeSinceLocalBallotStart =
        std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                              localBallotStart);

    // Scenario 2: if system time is behind the local prepare-start timer, the
    // network-based anchor can wedge the node, so use the local fallback.
    if (timeSinceLocalBallotStart > timeSinceNetworkLedgerStart)
    {
        return fallbackToPrepareStart();
    }

    // Scenario 1: widen the ahead-drift bound by the slow nomination we can
    // explain from the previous slot's timeout count.
    auto nominationTimeouts =
        mHerderSCPDriver.getNominationTimeouts(lastIndex).value_or(0);
    auto nominationBudget = std::chrono::milliseconds::zero();
    for (int64_t round = 1; round <= nominationTimeouts; ++round)
    {
        nominationBudget += mHerderSCPDriver.computeTimeout(
            static_cast<uint32_t>(round), /*isNomination=*/true);
    }

    // Scenario 1: if elapsed system time exceeds target plus explainable
    // nomination delay, treat it as clock-ahead drift and use the fallback.
    if (timeSinceNetworkLedgerStart > expectedClose + nominationBudget)
    {
        return fallbackToPrepareStart();
    }

    return now - timeSinceNetworkLedgerStart;
}

void
HerderImpl::setupTriggerNextLedger()
{
    // Invariant: core proceeds to vote for the next ledger only when it's _not_
    // applying to ensure block production does not conflict with ledger close.
    releaseAssert(!mLedgerManager.isApplying());

    // Invariant: tracking is equal to LCL when we trigger. This helps ensure
    // core emits SCP messages only for slots it can fully validate
    // (any closed ledger is fully validated)
    releaseAssert(isTracking());
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
    releaseAssert(trackingConsensusLedgerIndex() == lcl.header.ledgerSeq);
    releaseAssert(mLedgerManager.isSynced());

    mTriggerTimer.cancel();

    uint64_t nextIndex = nextConsensusLedgerIndex();
    auto lastIndex = trackingConsensusLedgerIndex();

    // if we're in sync, we setup mTriggerTimer
    // it may get cancelled if a more recent ledger externalizes

    std::chrono::milliseconds milliseconds =
        mLedgerManager.getExpectedLedgerCloseTime();

    auto now = mApp.getClock().now();

    auto lastLedgerStartingPoint =
        mApp.getConfig().EXPERIMENTAL_TRIGGER_TIMER
            ? triggerAnchorFromConsensusCloseTime(lastIndex, now, milliseconds)
            : triggerAnchorFromPrepareStart(lastIndex, now, milliseconds);

    // Adjust trigger time in case node's clock has drifted.
    // This ensures that next value to nominate is valid
    auto triggerTime = lastLedgerStartingPoint + milliseconds;

    if (triggerTime < now)
    {
        triggerTime = now;
    }

    auto triggerOffset = std::chrono::duration_cast<std::chrono::milliseconds>(
        triggerTime - now);

    auto minCandidateCt = lcl.header.scpValue.closeTime + 1;
    auto ctOffset = ctValidityOffset(minCandidateCt, triggerOffset);

    if (ctOffset > std::chrono::milliseconds::zero())
    {
        CLOG_INFO(Herder, "Adjust trigger time by {} ms", ctOffset.count());
        triggerTime += ctOffset;
    }

    // even if ballot protocol started before triggering, we just use that
    // time as reference point for triggering again (this may trigger right
    // away if externalizing took a long time)
    mTriggerTimer.expires_at(triggerTime);

    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        mTriggerTimer.async_wait(std::bind(&HerderImpl::triggerNextLedger, this,
                                           static_cast<uint32_t>(nextIndex),
                                           true),
                                 &VirtualTimer::onFailureNoop);
    }

#ifdef BUILD_TESTS
    mTriggerNextLedgerSeq = static_cast<uint32_t>(nextIndex);
#endif
}

// Returns the ledger index of the oldest ledger that it is safe to delete while
// still keeping all the information needed to publish checkpoints
static uint32_t
getSafeLedgerToDelete(uint32_t ledger, Config const& cfg)
{
    // Calculate the minimum of ledger and/or any queued checkpoint.
    uint32_t ql = HistoryManager::getMinLedgerQueuedToPublish(cfg);
    uint32_t qmin = ql == 0 ? ledger : std::min(ql, ledger);

    // Next calculate, given qmin, the first ledger it'd be _safe to delete_
    // while still keeping everything required to publish. So if qmin is
    // (for example) 0x7f = 127, then we want to keep 64 ledgers before
    // that, and therefore can erase 0x3f = 63 and less.
    uint32_t freq = HistoryManager::getCheckpointFrequency(cfg);
    return qmin >= freq ? qmin - freq : 0;
}

void
HerderImpl::eraseOutsideRange(std::optional<uint32> minSlot,
                              std::optional<uint32> maxSlot)
{
    auto lastCheckpointSeq = getMostRecentCheckpointSeq();
    getHerderSCPDriver().purgeSlotsOutsideRange(minSlot, maxSlot,
                                                lastCheckpointSeq);
    mPendingEnvelopes.eraseOutsideRange(minSlot, maxSlot, lastCheckpointSeq);

    if (minSlot)
    {
        auto lastIndex = trackingConsensusLedgerIndex();
        mApp.getOverlayManager().clearLedgersBelow(*minSlot, lastIndex);
        uint32_t lmin = getSafeLedgerToDelete(*minSlot, mApp.getConfig());
        // To avoid blocking too long, don't delete more than one checkpoint of
        // history
        uint32_t const ledgersToDelete =
            HistoryManager::getCheckpointFrequency(mApp.getConfig());
        HerderPersistence::deleteOldEntries(
            mApp.getDatabase().getRawMiscSession(), lmin, ledgersToDelete);
    }
}

bool
HerderImpl::recvSCPQuorumSet(Hash const& hash, SCPQuorumSet const& qset)
{
    ZoneScoped;
    return mPendingEnvelopes.recvSCPQuorumSet(hash, qset);
}

bool
HerderImpl::recvTxSet(Hash const& hash, TxSetXDRFrameConstPtr txset)
{
    ZoneScoped;
    return mPendingEnvelopes.recvTxSet(hash, txset);
}

TxSetXDRFrameConstPtr
HerderImpl::getTxSet(Hash const& hash)
{
    return mPendingEnvelopes.getTxSet(hash);
}

SCPQuorumSetPtr
HerderImpl::getQSet(Hash const& qSetHash)
{
    return mHerderSCPDriver.getQSet(qSetHash);
}

uint32
HerderImpl::getMinLedgerSeqToAskPeers() const
{
    // computes the smallest ledger for which we *think* we need more SCP
    // messages
    // we ask for messages older than lcl in case they have SCP
    // messages needed by other peers
    auto low = mApp.getLedgerManager().getLastClosedLedgerNum() + 1;

    auto maxSlots = std::min<uint32>(mApp.getConfig().MAX_SLOTS_TO_REMEMBER,
                                     SCP_EXTRA_LOOKBACK_LEDGERS);

    if (low > maxSlots)
    {
        low -= maxSlots;
    }
    else
    {
        low = LedgerManager::GENESIS_LEDGER_SEQ;
    }

    // do not ask for slots we'd be dropping anyways
    auto herderLow = getMinLedgerSeqToRemember();
    low = std::max<uint32>(low, herderLow);

    return low;
}

uint32_t
HerderImpl::getMostRecentCheckpointSeq()
{
    auto lastIndex = trackingConsensusLedgerIndex();
    return HistoryManager::firstLedgerInCheckpointContaining(lastIndex,
                                                             mApp.getConfig());
}

void
HerderImpl::setInSyncAndTriggerNextLedger()
{
    // We either have not set trigger timer, or we're in the
    // middle of a consensus round. Either way, we do not want
    // to trigger ledger, as the node is already making progress
    if (mTriggerTimer.seq() > 0)
    {
        CLOG_DEBUG(Herder, "Skipping setInSyncAndTriggerNextLedger: "
                           "trigger timer already set");
        return;
    }

    // Bring Herder and LM in sync in case they aren't
    if (mLedgerManager.getState() == LedgerManager::LM_BOOTING_STATE)
    {
        mLedgerManager.moveToSynced();
    }

    // Trigger next ledger, without requiring Herder to properly track SCP
    auto lcl = mLedgerManager.getLastClosedLedgerNum();
    triggerNextLedger(lcl + 1, false);
}

// called to take a position during the next round
// uses the state in LedgerManager to derive a starting position
std::pair<TxSetXDRFrameConstPtr, ApplicableTxSetFrameConstPtr>
HerderImpl::buildCandidateTxSet(LedgerHeaderHistoryEntry const& lcl,
                                TimePoint lowerBoundCloseTimeOffset,
                                TimePoint upperBoundCloseTimeOffset)
{
    ZoneScoped;
    releaseAssert(threadIsMain());

    // The candidates are the flood targets, so their proposal builder holds
    // the already-validated frames of every routed tx — no mempool IPC fetch
    // and no frame rebuild (docs/direct-leader-flooding.md, streaming
    // proposal construction).
    PerPhaseTransactionList txPhases;
    TxFrameList classicTxs;
    TxFrameList sorobanTxs;
    mTxProposalBuilder.snapshot(classicTxs, sorobanTxs);

    CLOG_INFO(Herder,
              "Candidate leader snapshotted {} classic + {} soroban txs "
              "from the proposal builder",
              classicTxs.size(), sorobanTxs.size());

    bool const supportsSoroban = protocolVersionStartsFrom(
        lcl.header.ledgerVersion, SOROBAN_PROTOCOL_VERSION);
    if (!supportsSoroban && !sorobanTxs.empty())
    {
        CLOG_DEBUG(Herder,
                   "Ignoring {} Soroban transactions before Soroban "
                   "protocol support",
                   sorobanTxs.size());
    }
    txPhases.emplace_back(std::move(classicTxs));
    if (supportsSoroban)
    {
        txPhases.emplace_back(std::move(sorobanTxs));
    }

    PerPhaseTransactionList invalidTxPhases;
    invalidTxPhases.resize(txPhases.size());

    auto res = makeTxSetFromTransactions(txPhases, mApp,
                                         lowerBoundCloseTimeOffset,
                                         upperBoundCloseTimeOffset,
                                         invalidTxPhases);

    // NB: trim-rejected txs deliberately stay in the builder. The list
    // mixes permanently-invalid txs with not-yet-valid deep-chain txs
    // (the gate admits seq gaps up to MAX_SEQ_GAP_FOR_FLOODING; strict
    // sequencing holds here), and the latter become valid as their
    // predecessors apply — exactly like the Rust mempool, whose entries
    // also survive a failed proposal until inclusion or age-out.

    if (res.second)
    {
        CLOG_INFO(Herder, "Candidate leader built TX set with {} transactions",
                  res.first->sizeTxTotal());
    }
    return res;
}

bool
HerderImpl::pushOrCacheProposedTxSet(TxSetXDRFrameConstPtr const& proposedSet,
                                     Hash const& txSetHash,
                                     bool selfIsRound1Leader,
                                     uint32_t slotIndex)
{
    // Empty proposals are not proactively pushed, but must remain servable
    // when a third-or-later leader nominates one. This also covers a
    // candidate whose mempool-backed construction happened to produce an
    // empty set. Note: the overlay only supports GeneralizedTransactionSet
    // (protocol >= 20).
    if (!proposedSet->isGeneralizedTxSet())
    {
        return false;
    }

    GeneralizedTransactionSet xdrTxSet;
    proposedSet->toXDR(xdrTxSet);
    auto xdrBytes = xdr::xdr_to_opaque(xdrTxSet);

    if (proposedSet->sizeTxTotal() == 0)
    {
        mApp.getOverlayManager().cacheTxSet(txSetHash, xdrBytes);
        return false;
    }

    // Direct leader flooding, TxSet dissemination
    // (docs/direct-leader-flooding.md Step 5): the round-1 leader for the
    // slot being nominated pushes the full body to every peer, so receivers
    // have it by the time they process the nomination that references it --
    // removing the GetTxSet request round-trip from the nomination critical
    // path. Other candidate leaders cache their full set for the fetch
    // fallback; non-candidates cache only their canonical empty proposal.
    //
    // Round-1 leader is seeded by hash(N-2); for slot N = ledgerSeq + 1 with
    // lcl = N-1, that seed is exactly lcl.header.previousLedgerHash. Under
    // application-specific (non-self-biased) weights every node agrees on
    // this single leader, so exactly one node broadcasts.
    //
    // Only round-1 pushes proactively. If the slot advances to another
    // pre-routed candidate, receivers use the delayed request fallback. If
    // all pre-routed candidates fail, later leaders nominate the
    // already-cached empty set.
    if (mApp.getConfig().ARTIFICIALLY_DROP_NOMINATED_TX_SET_FOR_TESTING)
    {
        // Wedge-repro testing: the nominated set is neither pushed nor
        // cached (leader or not), so NO peer can obtain the body -- the
        // limit case of "leader delivery too slow". Only the empty-tx-set
        // recovery can unblock the slot.
        CLOG_INFO(Herder,
                  "TESTING: dropping nominated TX set {} (not pushed, "
                  "not cached)",
                  binToHex(txSetHash).substr(0, 8));
        return false;
    }
    if (selfIsRound1Leader &&
        !mApp.getConfig().ARTIFICIALLY_SUPPRESS_TX_SET_FLOOD_FOR_TESTING)
    {
        CLOG_DEBUG(Herder,
                   "Round-1 leader: eagerly broadcasting TX set {} to peers "
                   "for slot {}",
                   binToHex(txSetHash).substr(0, 8), slotIndex);
        mApp.getOverlayManager().broadcastTxSet(txSetHash, xdrBytes,
                                                slotIndex);
        return true;
    }
    // Non-leader, or a test simulating a flood miss: keep the set servable
    // for fetches without pushing it.
    mApp.getOverlayManager().cacheTxSet(txSetHash, xdrBytes);
    return false;
}

void
HerderImpl::maybePreBuildProposal()
{
    ZoneScoped;
    releaseAssert(threadIsMain());

    // Any previously pre-built proposal is for an older slot now.
    mPreBuiltProposal.reset();

    if (!getSCP().isValidator() || !isTracking() ||
        !mLedgerManager.isSynced() || mLedgerManager.isApplying())
    {
        return;
    }

    auto lcl = mLedgerManager.getLastClosedLedgerHeader();
    uint32_t const slotIndex = lcl.header.ledgerSeq + 1;
    auto const candidateLeaders = mHerderSCPDriver.computeLeaderSchedule(
        lcl.header.previousLedgerHash, slotIndex,
        mApp.getConfig().FLOOD_LEADER_COUNT);
    auto const selfID = mApp.getConfig().NODE_SEED.getPublicKey();
    if (candidateLeaders.empty() || candidateLeaders.front() != selfID)
    {
        // Only the round-1 leader pre-builds and eagerly pushes; other
        // candidates build at trigger time and cache for the fetch fallback.
        return;
    }

    // Conservative close-time window: the trigger clamps nextCloseTime to at
    // least lcl.closeTime + 1, so 1 is the lowest offset it can pick; the
    // upper bound is the same estimate the flood gate validates against
    // (expected close time x EXPECTED_CLOSE_TIME_MULT + drift). checkValid's
    // window semantics are monotone (TransactionFrame::isTooEarly/isTooLate),
    // so a set trimmed against [1, U] is valid at any exact offset o <= U
    // the trigger may pick. If the trigger fires later than U, it rebuilds.
    TimePoint const lowerOffset = 1;
    TimePoint const upperOffset = std::max<TimePoint>(
        lowerOffset, getUpperBoundCloseTimeOffset(
                         mApp, lcl.header.scpValue.closeTime));

    auto built = buildCandidateTxSet(lcl, lowerOffset, upperOffset);
    if (!built.second)
    {
        return;
    }
    auto proposedSet = built.first;
    std::shared_ptr<ApplicableTxSetFrame const> applicableSet(
        std::move(built.second));
    auto txSetHash = proposedSet->getContentsHash();

    mPendingEnvelopes.addTxSet(txSetHash, slotIndex, proposedSet);

    // Eager dissemination fills the trigger-anchor idle window: receivers
    // assemble (and, with eager validation, verify) the set while SCP is
    // quiet, taking the whole dissemination off the nomination critical
    // path. IPC-ordering invariant: this runs after
    // purgeOldSlotsAndProcessSCPQueue sent LEDGER_CLOSED(N-1) and after
    // pushLeaderSchedule switched the flood targets to slot N+1's leaders,
    // so shreds are attributed to the right slot and post-freeze tx arrivals
    // already route to the next leaders, not to this frozen proposal.
    bool const pushed =
        pushOrCacheProposedTxSet(proposedSet, txSetHash,
                                 /*selfIsRound1Leader=*/true, slotIndex);

    mSCPMetrics.mProposalPreBuilt.Mark();
    if (pushed)
    {
        mSCPMetrics.mProposalPrePushed.Mark();
    }

    mPreBuiltProposal =
        PreBuiltProposal{slotIndex,     lcl.hash,  proposedSet, applicableSet,
                         txSetHash,     lowerOffset, upperOffset};

    CLOG_DEBUG(Herder,
               "Pre-built TX set {} for slot {} at apply-finish "
               "(window [{}, {}], pushed={})",
               hexAbbrev(txSetHash), slotIndex, lowerOffset, upperOffset,
               pushed);
}

void
HerderImpl::triggerNextLedger(uint32_t ledgerSeqToTrigger,
                              bool checkTrackingSCP)
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(ledgerSeqToTrigger));

    auto isTrackingValid = isTracking() || !checkTrackingSCP;

    if (!isTrackingValid || !mLedgerManager.isSynced())
    {
        CLOG_DEBUG(Herder, "triggerNextLedger: skipping (out of sync) : {}",
                   mApp.getStateHuman());
        return;
    }

    // If applying, the next ledger will trigger voting
    if (mLedgerManager.isApplying())
    {
        // This can only happen when closing ledgers in parallel
        releaseAssert(mApp.getConfig().parallelLedgerClose());
        CLOG_DEBUG(Herder, "triggerNextLedger: skipping (applying) : {}",
                   mApp.getStateHuman());
        return;
    }

    // our first choice for this round's set is all the tx we have collected
    // during last few ledger closes
    // Since we are not currently applying, it is safe to use read-only LCL, as
    // it's guaranteed to be up-to-date
    auto lcl = mLedgerManager.getLastClosedLedgerHeader();

    // We pick as next close time the current time unless it's before the last
    // close time. We don't know how much time it will take to reach consensus
    // so this is the most appropriate value to use as closeTime.
    uint64_t nextCloseTime =
        VirtualClock::to_time_t(mApp.getClock().system_now());
    if (ledgerSeqToTrigger == lcl.header.ledgerSeq + 1)
    {
        auto it = mDriftCTSlidingWindow.find(ledgerSeqToTrigger);
        if (it == mDriftCTSlidingWindow.end())
        {
            // Record local close time _before_ it gets adjusted to be valid
            // below
            mDriftCTSlidingWindow[ledgerSeqToTrigger] =
                std::make_pair(nextCloseTime, std::nullopt);
            while (mDriftCTSlidingWindow.size() >
                   CLOSE_TIME_DRIFT_LEDGER_WINDOW_SIZE)
            {
                mDriftCTSlidingWindow.erase(mDriftCTSlidingWindow.begin());
            }
        }
        else
        {
            CLOG_WARNING(Herder,
                         "Herder::triggerNextLedger called twice on ledger {}",
                         ledgerSeqToTrigger);
        }
    }

    if (nextCloseTime <= lcl.header.scpValue.closeTime)
    {
        nextCloseTime = lcl.header.scpValue.closeTime + 1;
    }

    // Ensure we're about to nominate a value with valid close time
    auto isCtValid =
        ctValidityOffset(nextCloseTime) == std::chrono::milliseconds::zero();

    if (!isCtValid)
    {
        CLOG_WARNING(Herder,
                     "Invalid close time selected ({}), skipping nomination",
                     nextCloseTime);
        return;
    }

    // Protocols including the "closetime change" (CAP-0034) externalize
    // the exact closeTime contained in the StellarValue with the best
    // transaction set, so we know the exact closeTime against which to
    // validate here -- 'nextCloseTime'.  (The _offset_, therefore, is
    // the difference between 'nextCloseTime' and the last ledger close time.)
    TimePoint upperBoundCloseTimeOffset, lowerBoundCloseTimeOffset;
    upperBoundCloseTimeOffset = nextCloseTime - lcl.header.scpValue.closeTime;
    lowerBoundCloseTimeOffset = upperBoundCloseTimeOffset;

    uint32_t const slotIndex = lcl.header.ledgerSeq + 1;
    auto const candidateLeaders = mHerderSCPDriver.computeLeaderSchedule(
        lcl.header.previousLedgerHash, slotIndex,
        mApp.getConfig().FLOOD_LEADER_COUNT);
    auto const selfID = mApp.getConfig().NODE_SEED.getPublicKey();
    bool const isValidator = getSCP().isValidator();
    bool const selfIsCandidateLeader =
        isValidator &&
        std::find(candidateLeaders.begin(), candidateLeaders.end(), selfID) !=
            candidateLeaders.end();

    TxSetXDRFrameConstPtr proposedSet;
    // Owns the applicable frame when built in this call; on pre-built reuse
    // the frame stays owned by mPreBuiltProposal and only the observing
    // pointer below is set.
    ApplicableTxSetFrameConstPtr applicableProposedSet;
    ApplicableTxSetFrame const* applicableForValidity = nullptr;
    Hash txSetHash;

    bool reusedPreBuiltProposal = false;
    if (selfIsCandidateLeader && mPreBuiltProposal &&
        mPreBuiltProposal->mSlotIndex == slotIndex &&
        mPreBuiltProposal->mLclHash == lcl.hash &&
        lowerBoundCloseTimeOffset >= mPreBuiltProposal->mLowerOffset &&
        upperBoundCloseTimeOffset <= mPreBuiltProposal->mUpperOffset)
    {
        // The proposal pre-built (and eagerly pushed) at apply-finish is
        // valid for this trigger's exact close-time offset: every tx was
        // trimmed against a window covering it. Reuse it -- the whole build
        // and dissemination happened off the nomination critical path.
        proposedSet = mPreBuiltProposal->mProposedSet;
        applicableForValidity = mPreBuiltProposal->mApplicableSet.get();
        reusedPreBuiltProposal = true;
        // scp.txset.candidate-build tracks which proposal path the trigger
        // took (candidate vs empty fallback), whether built now or reused.
        mSCPMetrics.mCandidateTxSetBuild.Mark();
        mSCPMetrics.mProposalPreBuildReused.Mark();
        CLOG_DEBUG(Herder, "Reusing pre-built TX set {} for slot {}",
                   hexAbbrev(mPreBuiltProposal->mTxSetHash), slotIndex);
    }
    else if (selfIsCandidateLeader)
    {
        if (mPreBuiltProposal && mPreBuiltProposal->mSlotIndex == slotIndex)
        {
            // Pre-built but unusable: the LCL moved, or the trigger fired
            // later than the pre-trim window allows. Rebuild at the exact
            // offset.
            mSCPMetrics.mProposalPreBuildStale.Mark();
            CLOG_DEBUG(Herder,
                       "Pre-built TX set for slot {} is stale "
                       "(lclMatch={}, offset {} vs window [{}, {}]); "
                       "rebuilding",
                       slotIndex, mPreBuiltProposal->mLclHash == lcl.hash,
                       upperBoundCloseTimeOffset,
                       mPreBuiltProposal->mLowerOffset,
                       mPreBuiltProposal->mUpperOffset);
        }
        std::tie(proposedSet, applicableProposedSet) = buildCandidateTxSet(
            lcl, lowerBoundCloseTimeOffset, upperBoundCloseTimeOffset);
        if (!applicableProposedSet)
        {
            releaseAssert(!mApp.getConfig().FORCE_SCP);
            return;
        }
        applicableForValidity = applicableProposedSet.get();
        mSCPMetrics.mCandidateTxSetBuild.Mark();
    }
    else
    {
        // Nodes outside the pre-routed candidate-leader window construct the
        // canonical empty set as their cheap liveness proposal. If nomination
        // advances past the routed candidates, the newly elected leader can
        // therefore make progress without having built the full mempool.
        proposedSet = TxSetXDRFrame::makeEmpty(lcl);
        applicableProposedSet =
            proposedSet->prepareForApply(mApp, lcl.header);
        releaseAssert(applicableProposedSet);
        applicableForValidity = applicableProposedSet.get();
        CLOG_DEBUG(Herder,
                   "Node is outside the first {} candidate leaders for slot "
                   "{}; using canonical empty TX set",
                   candidateLeaders.size(), slotIndex);
        if (isValidator)
        {
            mSCPMetrics.mEmptyTxSetFallback.Mark();
        }
    }

    txSetHash = proposedSet->getContentsHash();

    // Cache only this node's selected proposal: a mempool-backed set for the
    // first candidate leaders, or the canonical empty set for everyone else.
    // Keyed under the exact offset this trigger chose; a reused pre-built
    // set was validated across a window covering it.
    releaseAssert(applicableForValidity);
    mHerderSCPDriver.cacheValidTxSet(*applicableForValidity, lcl,
                                     upperBoundCloseTimeOffset);

    if (!reusedPreBuiltProposal)
    {
        mPendingEnvelopes.addTxSet(txSetHash, slotIndex, proposedSet);

        bool const selfIsRound1Leader =
            !candidateLeaders.empty() && candidateLeaders.front() == selfID;
        pushOrCacheProposedTxSet(proposedSet, txSetHash, selfIsRound1Leader,
                                 slotIndex);
    }
    // else: the pre-built set was added and pushed (or cached, per the test
    // knobs) at apply-finish. Re-broadcasting here would bump the overlay's
    // latest-wins shred generation and cancel our own in-flight shreds.

    lcl = mLedgerManager.getLastClosedLedgerHeader();

    // no point in sending out a prepare:
    // externalize was triggered on a more recent ledger
    // Also skip trigger if side effects from `addTxSet` caused us to start
    // applying
    if (ledgerSeqToTrigger != lcl.header.ledgerSeq + 1 ||
        ledgerSeqToTrigger != slotIndex || mLedgerManager.isApplying())
    {
        return;
    }

    auto newUpgrades = emptyUpgradeSteps;

    // see if we need to include some upgrades
    std::vector<LedgerUpgrade> upgrades;
    {
        CheckValidLedgerViewWrapper ledgerView(mApp);
        upgrades = mUpgrades.createUpgradesFor(lcl.header, ledgerView,
                                               mApp.getConfig());
    }
    for (auto const& upgrade : upgrades)
    {
        Value v(xdr::xdr_to_opaque(upgrade));
        if (v.size() >= UpgradeType::max_size())
        {
            CLOG_ERROR(
                Herder,
                "HerderImpl::triggerNextLedger exceeded size for upgrade "
                "step (got {} ) for upgrade type {}",
                v.size(), upgrade.type());
            CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        }
        else
        {
            newUpgrades.emplace_back(v.begin(), v.end());
        }
    }

    getHerderSCPDriver().recordSCPEvent(slotIndex, true);

    // If we are not a validating node we stop here and don't start nomination
    if (!isValidator)
    {
        CLOG_DEBUG(Herder, "Non-validating node, skipping nomination (SCP).");
        return;
    }

    StellarValue newProposedValue = makeStellarValue(
        txSetHash, nextCloseTime, newUpgrades, mApp.getConfig().NODE_SEED);
    mHerderSCPDriver.nominate(slotIndex, newProposedValue, proposedSet,
                              lcl.header.scpValue);
}

void
HerderImpl::setUpgrades(Upgrades::UpgradeParameters const& upgrades)
{
    mUpgrades.setParameters(upgrades, mApp.getConfig());
    persistUpgrades();

    auto desc = mUpgrades.toString();

    if (!desc.empty())
    {
        auto message =
            fmt::format(FMT_STRING("Armed with network upgrades: {}"), desc);
        auto prev = mApp.getStatusManager().getStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
        if (prev != message)
        {
            CLOG_INFO(Herder, "{}", message);
            mApp.getStatusManager().setStatusMessage(
                StatusCategory::REQUIRES_UPGRADES, message);
        }
    }
    else
    {
        CLOG_INFO(Herder, "Network upgrades cleared");
        mApp.getStatusManager().removeStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
    }
}

std::string
HerderImpl::getUpgradesJson()
{
    auto ledgerView = CheckValidLedgerViewWrapper(mApp);
    return mUpgrades.getParameters().toDebugJson(ledgerView);
}

void
HerderImpl::setFilteredAccounts(std::set<AccountID> const& accounts)
{
}

void
HerderImpl::forceSCPStateIntoSyncWithLastClosedLedger()
{
    auto const& header = mLedgerManager.getLastClosedLedgerHeader().header;
    setTrackingSCPState(header.ledgerSeq, header.scpValue,
                        /* isTrackingNetwork */ true);
}

bool
HerderImpl::resolveNodeID(std::string const& s, PublicKey& retKey)
{
    bool r = mApp.getConfig().resolveNodeID(s, retKey);
    if (!r)
    {
        if (s.size() > 1 && s[0] == '@')
        {
            std::string arg = s.substr(1);
            getSCP().processSlotsDescendingFrom(
                std::numeric_limits<uint64>::max(), [&](uint64_t seq) {
                    getSCP().processCurrentState(
                        seq,
                        [&](SCPEnvelope const& e) {
                            std::string curK =
                                KeyUtils::toStrKey(e.statement.nodeID);
                            if (curK.compare(0, arg.size(), arg) == 0)
                            {
                                retKey = e.statement.nodeID;
                                r = true;
                                return false;
                            }
                            return true;
                        },
                        true);

                    return !r;
                });
        }
    }
    return r;
}

Json::Value
HerderImpl::getJsonInfo(size_t limit, bool fullKeys)
{
    Json::Value ret;
    ret["you"] = mApp.getConfig().toStrKey(
        mApp.getConfig().NODE_SEED.getPublicKey(), fullKeys);

    ret["scp"] = getSCP().getJsonInfo(limit, fullKeys);
    ret["queue"] = mPendingEnvelopes.getJsonInfo(limit);
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumIntersectionInfo(bool fullKeys) const
{
    Json::Value ret;
    ret["intersection"] =
        mLastQuorumMapIntersectionState->enjoysQuorunIntersection();
    ret["node_count"] =
        static_cast<Json::UInt64>(mLastQuorumMapIntersectionState->mNumNodes);
    ret["last_check_ledger"] = static_cast<Json::UInt64>(
        mLastQuorumMapIntersectionState->mLastCheckLedger);
    if (mLastQuorumMapIntersectionState->enjoysQuorunIntersection())
    {
        Json::Value critical;
        for (auto const& group :
             mLastQuorumMapIntersectionState->mIntersectionCriticalNodes)
        {
            Json::Value jg;
            for (auto const& k : group)
            {
                auto s = mApp.getConfig().toStrKey(k, fullKeys);
                jg.append(s);
            }
            critical.append(jg);
        }
        ret["critical"] = critical;
    }
    else
    {
        ret["last_good_ledger"] = static_cast<Json::UInt64>(
            mLastQuorumMapIntersectionState->mLastGoodLedger);
        Json::Value split, a, b;
        auto const& pair = mLastQuorumMapIntersectionState->mPotentialSplit;
        for (auto const& k : pair.first)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            a.append(s);
        }
        for (auto const& k : pair.second)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            b.append(s);
        }
        split.append(a);
        split.append(b);
        ret["potential_split"] = split;
    }
    return ret;
}

Json::Value
HerderImpl::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                              uint64 index)
{
    Json::Value ret;
    ret["node"] = mApp.getConfig().toStrKey(id, fullKeys);
    ret["qset"] = getSCP().getJsonQuorumInfo(id, summary, fullKeys, index);

    bool isSelf = id == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf)
    {
        if (mLastQuorumMapIntersectionState->hasAnyResults())
        {
            ret["transitive"] =
                getJsonTransitiveQuorumIntersectionInfo(fullKeys);
        }

        ret["qset"]["lag_ms"] =
            getHerderSCPDriver().getQsetLagInfo(summary, fullKeys);
        ret["qset"]["cost"] =
            mPendingEnvelopes.getJsonValidatorCost(summary, fullKeys, index);
        ret["maybe_dead_nodes"] = mHerderSCPDriver.getMaybeDeadNodes(fullKeys);
    }
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumInfo(NodeID const& rootID, bool summary,
                                        bool fullKeys)
{
    Json::Value ret;
    bool isSelf = rootID == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf && mLastQuorumMapIntersectionState->hasAnyResults())
    {
        ret = getJsonTransitiveQuorumIntersectionInfo(fullKeys);
    }

    Json::Value& nodes = ret["nodes"];

    auto& q = mPendingEnvelopes.getCurrentlyTrackedQuorum();

    auto rootLatest = getSCP().getLatestMessage(rootID);
    std::map<Value, int> knownValues;

    // walk the quorum graph, starting at id
    UnorderedSet<NodeID> visited;
    std::vector<NodeID> next;
    next.push_back(rootID);
    visited.emplace(rootID);
    int distance = 0;
    int valGenID = 0;
    while (!next.empty())
    {
        std::vector<NodeID> frontier(std::move(next));
        next.clear();
        std::sort(frontier.begin(), frontier.end());
        for (auto const& id : frontier)
        {
            Json::Value cur;
            valGenID++;
            cur["node"] = mApp.getConfig().toStrKey(id, fullKeys);
            if (!summary)
            {
                cur["distance"] = distance;
            }
            auto it = q.find(id);
            std::string status;
            if (it != q.end())
            {
                auto qSet = it->second.mQuorumSet;
                if (qSet)
                {
                    if (!summary)
                    {
                        cur["qset"] =
                            getSCP().getLocalNode()->toJson(*qSet, fullKeys);
                    }
                    LocalNode::forAllNodes(*qSet, [&](NodeID const& n) {
                        auto b = visited.emplace(n);
                        if (b.second)
                        {
                            next.emplace_back(n);
                        }
                        return true;
                    });
                }
                auto latest = getSCP().getLatestMessage(id);
                if (latest)
                {
                    auto vals = Slot::getStatementValues(latest->statement);
                    // updates the `knownValues` map, and generate a unique ID
                    // for the value (heuristic to group votes)
                    int trackingValID = -1;
                    Value const* trackingValue = nullptr;
                    for (auto const& v : vals)
                    {
                        auto p =
                            knownValues.insert(std::make_pair(v, valGenID));
                        if (p.first->second > trackingValID)
                        {
                            trackingValID = p.first->second;
                            trackingValue = &v;
                        }
                    }

                    cur["heard"] =
                        static_cast<Json::UInt64>(latest->statement.slotIndex);
                    if (!summary)
                    {
                        cur["value"] = trackingValue
                                           ? mHerderSCPDriver.getValueString(
                                                 *trackingValue)
                                           : "";
                        cur["value_id"] = trackingValID;
                    }
                    // give a sense of how this node is doing compared to rootID
                    if (rootLatest)
                    {
                        if (latest->statement.slotIndex <
                            rootLatest->statement.slotIndex)
                        {
                            status = "behind";
                        }
                        else if (latest->statement.slotIndex >
                                 rootLatest->statement.slotIndex)
                        {
                            status = "ahead";
                        }
                        else
                        {
                            status = "tracking";
                        }
                    }
                }
                else
                {
                    status = "missing";
                }
            }
            else
            {
                status = "unknown";
            }
            cur["status"] = status;
            nodes.append(cur);
        }
        distance++;
    }
    ret["maybe_dead_nodes"] = mHerderSCPDriver.getMaybeDeadNodes(fullKeys);
    return ret;
}

QuorumTracker::QuorumMap const&
HerderImpl::getCurrentlyTrackedQuorum() const
{
    return mPendingEnvelopes.getCurrentlyTrackedQuorum();
}

static Hash
getQmapHash(QuorumTracker::QuorumMap const& qmap)
{
    ZoneScoped;
    SHA256 hasher;
    std::map<NodeID, QuorumTracker::NodeInfo> ordered_map(qmap.begin(),
                                                          qmap.end());
    for (auto const& pair : ordered_map)
    {
        hasher.add(xdr::xdr_to_opaque(pair.first));
        if (pair.second.mQuorumSet)
        {
            hasher.add(xdr::xdr_to_opaque(*(pair.second.mQuorumSet)));
        }
        else
        {
            hasher.add("\0");
        }
    }
    return hasher.finish();
}

void
HerderImpl::checkAndMaybeReanalyzeQuorumMapV2()
{
    ZoneScoped;
    if (!mApp.getConfig().QUORUM_INTERSECTION_CHECKER)
    {
        return;
    }
    auto& qmap = getCurrentlyTrackedQuorum();
    Hash curr = getQmapHash(qmap);
    if (mLastQuorumMapIntersectionState->mLastCheckQuorumMapHash == curr)
    {
        // Everything's stable, nothing to do.
        return;
    }
    if (mLastQuorumMapIntersectionState->mRecalculating)
    {
        if (mLastQuorumMapIntersectionState->mCheckingQuorumMapHash == curr)
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, already analyzing new "
                               "configuration.");
        }
        else
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has changed,"
                               "however the previous analysis is still "
                               "in progress, the new analysis will start after "
                               "the previous one finishes or gets interrupted "
                               "by the timer");
        }
        return;
    }

    CLOG_INFO(Herder,
              "Transitive closure of quorum has changed, re-analyzing.");
    mLastQuorumMapIntersectionState->reset(mApp);
    mLastQuorumMapIntersectionState->mRecalculating = true;
    mLastQuorumMapIntersectionState->mCheckingQuorumMapHash = curr;
    quorum_checker::runQuorumIntersectionCheckAsync(
        mApp, curr, trackingConsensusLedgerIndex(),
        mLastQuorumMapIntersectionState->mTmpDir->getName(), qmap,
        mLastQuorumMapIntersectionState, mApp.getProcessManager(),
        mApp.getConfig().QUORUM_INTERSECTION_CHECKER_TIME_LIMIT_MS,
        mApp.getConfig().QUORUM_INTERSECTION_CHECKER_MEMORY_LIMIT_BYTES,
        true /*analyzeCriticalGroups*/);
}

void
HerderImpl::checkAndMaybeReanalyzeQuorumMap()
{
    if (!mApp.getConfig().QUORUM_INTERSECTION_CHECKER)
    {
        return;
    }
    ZoneScoped;
    QuorumTracker::QuorumMap const& qmap = getCurrentlyTrackedQuorum();
    Hash curr = getQmapHash(qmap);
    if (mLastQuorumMapIntersectionState->mLastCheckQuorumMapHash == curr)
    {
        // Everything's stable, nothing to do.
        return;
    }

    if (mLastQuorumMapIntersectionState->mRecalculating)
    {
        // Already recalculating. If we're recalculating for the hash we want,
        // we do nothing, just wait for it to finish. If we're recalculating for
        // a hash that has changed _again_ (since the calculation started), we
        // _interrupt_ the calculation-in-progress: we'll return to this
        // function on the next externalize and start a new calculation for the
        // new hash we want.
        if (mLastQuorumMapIntersectionState->mCheckingQuorumMapHash == curr)
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, already analyzing new "
                               "configuration.");
        }
        else
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, interrupting existing "
                               "analysis.");
            mLastQuorumMapIntersectionState->mInterruptFlag = true;
        }
    }
    else
    {
        CLOG_INFO(Herder,
                  "Transitive closure of quorum has changed, re-analyzing.");
        // Not currently recalculating: start doing so.
        mLastQuorumMapIntersectionState->mRecalculating = true;
        mLastQuorumMapIntersectionState->mInterruptFlag = false;
        mLastQuorumMapIntersectionState->mCheckingQuorumMapHash = curr;
        auto& cfg = mApp.getConfig();
        auto seed = getGlobalRandomEngine()();

        auto ledger = trackingConsensusLedgerIndex();
        auto nNodes = qmap.size();
        auto hState = mLastQuorumMapIntersectionState;
        auto& app = mApp;
        auto worker = [curr, ledger, nNodes, qmap, cfg, seed, &app, hState] {
            try
            {
                ZoneScoped;
                bool ok = false;
                std::pair<std::vector<PublicKey>, std::vector<PublicKey>> split;
                auto qic = QuorumIntersectionChecker::create(
                    qmap, cfg, hState->mInterruptFlag, seed);
                ok = qic->networkEnjoysQuorumIntersection();
                split = qic->getPotentialSplit();
                std::set<std::set<PublicKey>> critical;
                if (ok)
                {
                    // Only bother calculating the _critical_ groups if we're
                    // intersecting; if not intersecting we should finish ASAP
                    // and raise an alarm.
                    auto cb = [&hState, seed](
                                  QuorumIntersectionChecker::QuorumSetMap const&
                                      qSetMap,
                                  std::optional<Config> const& config) -> bool {
                        auto checker = QuorumIntersectionChecker::create(
                            qSetMap, config, hState->mInterruptFlag, seed,
                            /*quiet=*/true);
                        return checker->networkEnjoysQuorumIntersection();
                    };
                    critical = QuorumIntersectionChecker::
                        getIntersectionCriticalGroups(
                            toQuorumIntersectionMap(qmap), cfg, cb);
                }
                app.postOnMainThread(
                    [ok, curr, ledger, nNodes, split, critical, hState, &app] {
                        hState->reset(app);

                        hState->mNumNodes = nNodes;
                        hState->mLastCheckLedger = ledger;
                        hState->mLastCheckQuorumMapHash = curr;
                        hState->mPotentialSplit = split;
                        hState->mIntersectionCriticalNodes = critical;
                        if (ok)
                        {
                            hState->mLastGoodLedger = ledger;
                        }
                    },
                    "QuorumIntersectionChecker finished");
            }
            catch (QuorumIntersectionChecker::InterruptedException&)
            {
                CLOG_DEBUG(Herder,
                           "Quorum transitive closure analysis interrupted.");
                app.postOnMainThread([hState, &app] { hState->reset(app); },
                                     "QuorumIntersectionChecker interrupted");
            }
            catch (RustQuorumCheckerError const& e)
            {
                CLOG_DEBUG(Herder,
                           "Quorum transitive closure analysis failed due to "
                           "Rust solver error: {}",
                           e.what());
                app.postOnMainThread([hState, &app] { hState->reset(app); },
                                     "QuorumIntersectionChecker rust error");
            }
        };
        mApp.postOnBackgroundThread(worker, "QuorumIntersectionChecker");
    }
}

void
HerderImpl::persistSCPState(uint64 slot)
{
    ZoneScoped;
    if (slot < mLastSlotSaved)
    {
        return;
    }

    mLastSlotSaved = slot;
    // saves SCP messages and related data (transaction sets, quorum sets)
    PersistedSCPState scpState;
    scpState.v(1);

    auto& latestEnvs = scpState.v1().scpEnvelopes;
    std::map<Hash, TxSetXDRFrameConstPtr> txSets;
    std::map<Hash, SCPQuorumSetPtr> quorumSets;

    for (auto const& e : getSCP().getLatestMessagesSend(slot))
    {
        latestEnvs.emplace_back(e);

        // saves transaction sets referred by the statement
        for (auto const& h : getValidatedTxSetHashes(e))
        {
            auto txSet = mPendingEnvelopes.getTxSet(h);
            if (txSet && !mApp.getPersistentState().hasTxSet(h))
            {
                txSets.insert(std::make_pair(h, txSet));
            }
        }
        Hash qsHash = Slot::getCompanionQuorumSetHashFromStatement(e.statement);
        SCPQuorumSetPtr qSet = mPendingEnvelopes.getQSet(qsHash);
        if (qSet)
        {
            quorumSets.insert(std::make_pair(qsHash, qSet));
        }
    }

    auto& latestQSets = scpState.v1().quorumSets;
    for (auto it : quorumSets)
    {
        latestQSets.emplace_back(*it.second);
    }

    stellar::Value latestSCPData;

    std::unordered_map<Hash, std::string> txSetsToPersist;
    for (auto it : txSets)
    {
        StoredTransactionSet tempTxSet;
        it.second->storeXDR(tempTxSet);
        txSetsToPersist.emplace(
            it.first, decoder::encode_b64(xdr::xdr_to_opaque(tempTxSet)));
    }

    latestSCPData = xdr::xdr_to_opaque(scpState);

    std::string encodedScpState = decoder::encode_b64(latestSCPData);

    mApp.getPersistentState().setSCPStateV1ForSlot(slot, encodedScpState,
                                                   txSetsToPersist);
}

void
HerderImpl::restoreSCPState()
{
    ZoneScoped;

    // Delete any old tx sets
    purgeOldPersistedTxSets();

    // Load all known tx sets
    auto latestTxSets = mApp.getPersistentState().getTxSetsForAllSlots();
    for (auto const& [_, txSet] : latestTxSets)
    {
        try
        {
            std::vector<uint8_t> buffer;
            decoder::decode_b64(txSet, buffer);

            StoredTransactionSet storedSet;
            xdr::xdr_from_opaque(buffer, storedSet);
            TxSetXDRFrameConstPtr cur =
                TxSetXDRFrame::makeFromStoredTxSet(storedSet);
            Hash h = cur->getContentsHash();
            mPendingEnvelopes.addTxSet(h, 0, cur);
        }
        catch (std::exception& e)
        {
            // we may have exceptions when upgrading the protocol
            // this should be the only time we get exceptions decoding old
            // messages.
            CLOG_INFO(Herder,
                      "Error while restoring old tx sets, "
                      "proceeding without them : {}",
                      e.what());
        }
    }

    // load saved state from database
    auto latest64 = mApp.getPersistentState().getSCPStateAllSlots();

    for (auto const& [_, state] : latest64)
    {
        try
        {
            std::vector<uint8_t> buffer;
            decoder::decode_b64(state, buffer);

            PersistedSCPState scpState;
            xdr::xdr_from_opaque(buffer, scpState);
            for (auto const& qset : scpState.v1().quorumSets)
            {
                Hash hash = xdrSha256(qset);
                mPendingEnvelopes.addSCPQuorumSet(hash, qset);
            }
            for (auto const& e : scpState.v1().scpEnvelopes)
            {
                auto envW = getHerderSCPDriver().wrapEnvelope(e);
                getSCP().setStateFromEnvelope(e.statement.slotIndex, envW);
                mLastSlotSaved =
                    std::max<uint64>(mLastSlotSaved, e.statement.slotIndex);
            }
        }
        catch (std::exception& e)
        {
            // we may have exceptions when upgrading the protocol
            // this should be the only time we get exceptions decoding old
            // messages.
            CLOG_INFO(Herder,
                      "Error while restoring old scp messages, "
                      "proceeding without them : {}",
                      e.what());
        }
        mPendingEnvelopes.rebuildQuorumTrackerState();
    }
}

void
HerderImpl::persistUpgrades()
{
    ZoneScoped;
    releaseAssert(threadIsMain());
    auto s = mUpgrades.getParameters().toJson();
    mApp.getPersistentState().setMiscState(PersistentState::kLedgerUpgrades, s);
}

void
HerderImpl::restoreUpgrades()
{
    ZoneScoped;
    releaseAssert(threadIsMain());

    std::string s = mApp.getPersistentState().getState(
        PersistentState::kLedgerUpgrades, mApp.getDatabase().getMiscSession());
    if (!s.empty())
    {
        Upgrades::UpgradeParameters p;

        p.fromJson(s);
        try
        {
            // use common code to set status
            setUpgrades(p);
        }
        catch (std::exception& e)
        {
            CLOG_INFO(Herder,
                      "Error restoring upgrades '{}' with upgrades '{}'",
                      e.what(), s);
        }
    }
}

void
HerderImpl::maybeHandleUpgrade()
{
    ZoneScoped;

    uint32_t diff = 0;
    {
        if (protocolVersionIsBefore(mApp.getLedgerManager()
                                        .getLastClosedLedgerHeader()
                                        .header.ledgerVersion,
                                    SOROBAN_PROTOCOL_VERSION))
        {
            // no-op on any earlier protocol
            return;
        }
        auto const& conf =
            mApp.getLedgerManager().getLastClosedSorobanNetworkConfig();

        auto maybeNewMaxTxSize = saturatingAdd<uint32_t>(
            conf.txMaxSizeBytes(), getFlowControlExtraBuffer());
        if (maybeNewMaxTxSize > mMaxTxSize)
        {
            diff = maybeNewMaxTxSize - mMaxTxSize;
        }
        // mMaxTxSize may decrease post-upgrade, always choose the max between
        // classic tx size (static) and Soroban max tx size
        mMaxTxSize = std::max(getMaxClassicTxSize(), maybeNewMaxTxSize);
    }

    // Note: With Rust overlay, no per-peer notifications needed here
    // The overlay handles message sizes internally
}

void
HerderImpl::start()
{
    mMaxTxSize = mApp.getHerder().getMaxClassicTxSize();
    {
        uint32_t version = mApp.getLedgerManager()
                               .getLastClosedLedgerHeader()
                               .header.ledgerVersion;
        if (protocolVersionStartsFrom(version, SOROBAN_PROTOCOL_VERSION))
        {
            auto const& conf =
                mApp.getLedgerManager().getLastClosedSorobanNetworkConfig();
            mMaxTxSize =
                std::max(mMaxTxSize,
                         saturatingAdd<uint32_t>(conf.txMaxSizeBytes(),
                                                 getFlowControlExtraBuffer()));
        }
    }

    auto const& cfg = mApp.getConfig();
    // Core will calculate default values automatically
    bool calculateDefaults = cfg.PEER_FLOOD_READING_CAPACITY_BYTES == 0 &&
                             cfg.FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES == 0;

    if (!calculateDefaults &&
        !(cfg.PEER_FLOOD_READING_CAPACITY_BYTES -
              cfg.FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES >=
          mMaxTxSize))
    {
        std::string msg = fmt::format(
            "Invalid configuration: the difference between "
            "PEER_FLOOD_READING_CAPACITY_BYTES ({}) and "
            "FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES ({}) must be at"
            " least {} bytes",
            cfg.PEER_FLOOD_READING_CAPACITY_BYTES,
            cfg.FLOW_CONTROL_SEND_MORE_BATCH_SIZE_BYTES, mMaxTxSize);
        throw std::runtime_error(msg);
    }

    // setup a sufficient state that we can participate in consensus
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

    if (!mApp.getConfig().FORCE_SCP &&
        lcl.header.ledgerSeq == LedgerManager::GENESIS_LEDGER_SEQ)
    {
        // if we're on genesis ledger, there is no point in claiming
        // that we're "in sync"
        setTrackingSCPState(lcl.header.ledgerSeq, lcl.header.scpValue,
                            /* isTrackingNetwork */ false);
    }
    else
    {
        setTrackingSCPState(lcl.header.ledgerSeq, lcl.header.scpValue,
                            /* isTrackingNetwork */ true);
        trackingHeartBeat();
        // Load SCP state from the database
        restoreSCPState();
    }

    restoreUpgrades();
    startTxSetGCTimer();
    startCheckForDeadNodesInterval();

    auto& bap = mApp.getBannedAccountsPersistor();
    if (!mApp.getConfig().FILTERED_G_ADDRESSES.empty())
    {
        CLOG_WARNING(
            Herder,
            "FILTERED_G_ADDRESSES is deprecated and will be removed in a "
            "future release. The current {} address(es) will be stored in the "
            "database. You can safely remove FILTERED_G_ADDRESSES from the "
            "config. Use 'banaccounts'/'unbanaccounts' HTTP commands to manage "
            "banned accounts going forward.",
            mApp.getConfig().FILTERED_G_ADDRESSES.size());
        bap.addBannedAccounts(mApp.getConfig().FILTERED_G_ADDRESSES);
    }

    setFilteredAccounts(bap.getBannedAccounts());
    // RustOverlayManager is started automatically in OverlayManager::start()
    // which is called by ApplicationImpl::start() before Herder::start()
}

void
HerderImpl::startTxSetGCTimer()
{
    mTxSetGarbageCollectTimer.expires_from_now(TX_SET_GC_DELAY);
    mTxSetGarbageCollectTimer.async_wait(
        [this]() { purgeOldPersistedTxSets(); }, &VirtualTimer::onFailureNoop);
}

void
HerderImpl::purgeOldPersistedTxSets()
{
    ZoneScoped;

    try
    {
        auto hashesToDelete =
            mApp.getPersistentState().getTxSetHashesForAllSlots();
        for (auto const& [_, state] :
             mApp.getPersistentState().getSCPStateAllSlots())
        {
            try
            {
                std::vector<uint8_t> buffer;
                decoder::decode_b64(state, buffer);

                PersistedSCPState scpState;
                xdr::xdr_from_opaque(buffer, scpState);
                for (auto const& e : scpState.v1().scpEnvelopes)
                {
                    for (auto const& hash : getValidatedTxSetHashes(e))
                    {
                        hashesToDelete.erase(hash);
                    }
                }
            }
            catch (std::exception& e)
            {
                CLOG_ERROR(Herder, "Error while deleting old tx sets: {}",
                           e.what());
            }
        }
        mApp.getPersistentState().deleteTxSets(hashesToDelete);
        startTxSetGCTimer();
    }
    catch (std::exception& e)
    {
        CLOG_ERROR(Herder, "Error while deleting old tx sets: {}", e.what());
    }
}

void
HerderImpl::startCheckForDeadNodesInterval()
{
    mCheckForDeadNodesTimer.expires_from_now(CHECK_FOR_DEAD_NODES_MINUTES);
    mCheckForDeadNodesTimer.async_wait(
        [this]() {
            mHerderSCPDriver.startCheckForDeadNodesInterval();
            startCheckForDeadNodesInterval();
        },
        &VirtualTimer::onFailureNoop);
}

void
HerderImpl::trackingHeartBeat()
{
    releaseAssert(threadIsMain());
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return;
    }

    mOutOfSyncTimer.cancel();

    releaseAssert(isTracking());

    mTrackingTimer.expires_from_now(
        std::chrono::seconds(CONSENSUS_STUCK_TIMEOUT_SECONDS));
    mTrackingTimer.async_wait(
        [this]() {
            if (mApp.getLedgerManager().isApplying())
            {
                // if we're applying a ledger, it's possible that we're just
                // slow and the timer expired; reset the timer and wait until we
                // finished application
                trackingHeartBeat();
            }
            else
            {
                herderOutOfSync();
            }
        },
        &VirtualTimer::onFailureNoop);
}

UnorderedSet<LedgerKey>
HerderImpl::recomputeKeysToFilter(uint32_t protocolVersion) const
{
    if (!gIsProductionNetwork)
    {
        return UnorderedSet<LedgerKey>{};
    }

    auto filteredSet = [](size_t count,
                          auto const& arr) mutable -> UnorderedSet<LedgerKey> {
        UnorderedSet<LedgerKey> result;
        for (size_t i = 0; i < count; ++i)
        {
            LedgerKey key;
            fromOpaqueBase64(key, arr[i]);
            result.insert(key);
        }
        return result;
    };
    return filteredSet(KEYS_TO_FILTER_P24_COUNT, KEYS_TO_FILTER_P24);
}

void
HerderImpl::herderOutOfSync()
{
    ZoneScoped;
    // State switch from "tracking" to "out of sync" should only happen if
    // there are no ledgers queued to be applied. If there are ledgers
    // queued, it's possible the rest of the network is waiting for this
    // node to vote. In this case we should _still_ remain in tracking and
    // emit nomination; If the node does not hear anything from the network
    // after that, then node can go into out of sync recovery.
    releaseAssert(threadIsMain());
    releaseAssert(!mLedgerManager.isApplying());

    CLOG_WARNING(Herder, "Lost track of consensus");

    auto s = getJsonInfo(20).toStyledString();
    CLOG_WARNING(Herder, "Out of sync context: {}", s);

    mSCPMetrics.mLostSync.Mark();
    lostSync();

    releaseAssert(getState() == Herder::HERDER_SYNCING_STATE);
    mPendingEnvelopes.reportCostOutliersForSlot(trackingConsensusLedgerIndex(),
                                                false);

    startOutOfSyncTimer();

    processSCPQueue(true);
}

void
HerderImpl::getMoreSCPState()
{
    ZoneScoped;
    auto low = getMinLedgerSeqToAskPeers();
    CLOG_INFO(Herder, "Requesting SCP state from peers, ledger >= {}", low);

    // Request SCP state via Rust overlay - it will ask random peers
    mApp.getOverlayManager().getOverlayIPC().requestScpState(low);
}

bool
HerderImpl::verifyEnvelope(SCPEnvelope const& envelope)
{
    ZoneScoped;
    auto [b, _] = PubKeyUtils::verifySig(
        envelope.statement.nodeID, envelope.signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCP,
                           envelope.statement));
    if (b)
    {
        mSCPMetrics.mEnvelopeValidSig.Mark();
    }
    else
    {
        mSCPMetrics.mEnvelopeInvalidSig.Mark();
    }

    return b;
}
void
HerderImpl::signEnvelope(SecretKey const& s, SCPEnvelope& envelope)
{
    ZoneScoped;
    envelope.signature = s.sign(xdr::xdr_to_opaque(
        mApp.getNetworkID(), ENVELOPE_TYPE_SCP, envelope.statement));
}
bool
HerderImpl::verifyStellarValueSignature(StellarValue const& sv)
{
    ZoneScoped;
    // Empty-tx-set recovery (docs/direct-leader-flooding.md): an empty-tx-set
    // value carries the ORIGINAL proposal's signature in proposedValue, signed
    // over the original (txSetHash, closeTime). Verify against that, not the
    // (absent) top-level signature arm.
    if (sv.ext.v() == STELLAR_VALUE_EMPTY_TX_SET)
    {
        auto const& ov = sv.ext.proposedValue();
        auto [b, _] = PubKeyUtils::verifySig(
            ov.lcValueSignature.nodeID, ov.lcValueSignature.signature,
            xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCPVALUE,
                               ov.txSetHash, sv.closeTime));
        return b;
    }
    auto [b, _] = PubKeyUtils::verifySig(
        sv.ext.lcValueSignature().nodeID, sv.ext.lcValueSignature().signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCPVALUE,
                           sv.txSetHash, sv.closeTime));
    return b;
}

StellarValue
HerderImpl::makeStellarValue(Hash const& txSetHash, uint64_t closeTime,
                             xdr::xvector<UpgradeType, 6> const& upgrades,
                             SecretKey const& s)
{
    ZoneScoped;
    StellarValue sv;
    sv.ext.v(STELLAR_VALUE_SIGNED);
    sv.txSetHash = txSetHash;
    sv.closeTime = closeTime;
    sv.upgrades = upgrades;
    sv.ext.lcValueSignature().nodeID = s.getPublicKey();
    sv.ext.lcValueSignature().signature =
        s.sign(xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCPVALUE,
                                  sv.txSetHash, sv.closeTime));
    return sv;
}

bool
HerderImpl::isNewerNominationOrBallotSt(SCPStatement const& oldSt,
                                        SCPStatement const& newSt)
{
    return getSCP().isNewerNominationOrBallotSt(oldSt, newSt);
}
}
