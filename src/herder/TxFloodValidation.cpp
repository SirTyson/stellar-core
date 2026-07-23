// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/TxFloodValidation.h"
#include "crypto/Hex.h"
#include "herder/Herder.h"
#include "ledger/ImmutableLedgerView.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"
#include "main/Config.h"
#include "transactions/MutableTransactionResult.h"
#include "transactions/TransactionFrameBase.h"
#include "transactions/TransactionUtils.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/ProtocolVersion.h"

#include <Tracy.hpp>
#include <atomic>

namespace stellar
{

namespace
{

// Allow short per-account seqnum chains through the gate: there is no tx
// queue tracking pending predecessors (the mempool is fee-ordered only), so
// a tx whose seqnum is a small distance ahead of the account's current
// seqnum must still flood — its predecessors are in flight through some
// mempool, and the leader's trimInvalid enforces exact sequencing at
// nomination. Without this, submitting N txs from one account drops all but
// the first.
constexpr int64_t MAX_SEQ_GAP_FOR_FLOODING = 64;

// Per-batch shared state. Chunk tasks all hold the same Batch via shared_ptr;
// the last one to finish invokes the callback.
struct Batch
{
    Application& mApp;
    std::shared_ptr<std::vector<TransactionEnvelope> const> mEnvelopes;
    TxFloodVerdictCallback mCallback;
    ImmutableLedgerView mBaseView;
    uint64_t mUpperBoundCloseTimeOffset;
    std::optional<uint32_t> mValidationLedgerSeq;
    TxFloodVerdicts mVerdicts;
    std::atomic<size_t> mTasksRemaining;

    Batch(Application& app,
          std::shared_ptr<std::vector<TransactionEnvelope> const> envelopes,
          TxFloodVerdictCallback callback, ImmutableLedgerView&& baseView)
        : mApp(app)
        , mEnvelopes(std::move(envelopes))
        , mCallback(std::move(callback))
        , mBaseView(std::move(baseView))
        , mUpperBoundCloseTimeOffset(0)
        , mVerdicts(mEnvelopes->size(), 0)
        , mTasksRemaining(0)
    {
        auto const& header =
            mBaseView.getState().getLastClosedLedgerHeader().header;

        // Mirror of (main-thread-only) getUpperBoundCloseTimeOffset /
        // getExpectedLedgerCloseTime, computed from the snapshot so it is
        // valid on pool threads. The clock read is benign-racy in virtual
        // (test) clock mode; production uses the system clock.
        uint64_t currentTime =
            VirtualClock::to_time_t(mApp.getClock().system_now());
        uint64_t lastCloseTime = header.scpValue.closeTime;
        uint64_t closeTimeDrift =
            currentTime <= lastCloseTime ? 0 : currentTime - lastCloseTime;

        std::chrono::milliseconds expectedCloseTime;
        auto const& cfg = mApp.getConfig();
        if (auto overrideOp = cfg.getExpectedLedgerCloseTimeTestingOverride();
            overrideOp.has_value())
        {
            expectedCloseTime = *overrideOp;
        }
        else if (protocolVersionStartsFrom(header.ledgerVersion,
                                           ProtocolVersion::V_23))
        {
            expectedCloseTime = std::chrono::milliseconds(
                mBaseView.getState()
                    .getSorobanConfig()
                    .ledgerTargetCloseTimeMilliseconds());
        }
        else
        {
            expectedCloseTime =
                Herder::TARGET_LEDGER_CLOSE_TIME_BEFORE_PROTOCOL_VERSION_23_MS;
        }
        mUpperBoundCloseTimeOffset =
            std::chrono::duration_cast<std::chrono::seconds>(expectedCloseTime)
                    .count() *
                EXPECTED_CLOSE_TIME_MULT +
            closeTimeDrift;

        // Validate minSeqLedgerGap and LedgerBounds against the next
        // ledgerSeq, which is what will be used at apply time.
        if (protocolVersionStartsFrom(header.ledgerVersion,
                                      ProtocolVersion::V_19))
        {
            mValidationLedgerSeq = header.ledgerSeq + 1;
        }
    }
};

void
validateChunk(std::shared_ptr<Batch> const& batch, size_t begin, size_t end)
{
    ZoneScoped;
    CheckValidLedgerViewWrapper chunkView(batch->mBaseView);
    auto& app = batch->mApp;
#ifdef BUILD_TESTS
    // See TransactionQueue::canAdd on master for the overlay-only-mode
    // rationale: on-disk seqnums are frozen at genesis there, so the seqnum
    // equality check would reject every tx after the first.
    chunkView.mSkipSeqNumCheck = app.getRunInOverlayOnlyMode();
#endif
    auto diagnostics = DiagnosticEventManager::createDisabled();
    auto const& networkID = app.getNetworkID();
    uint32_t lclVersion = batch->mBaseView.getState()
                              .getLastClosedLedgerHeader()
                              .header.ledgerVersion;

    for (size_t i = begin; i < end; ++i)
    {
        auto const& env = (*batch->mEnvelopes)[i];
        TransactionFrameBasePtr tx;
        try
        {
            tx = TransactionFrameBase::makeTransactionFromWire(networkID, env);
        }
        catch (std::exception const&)
        {
            // Malformed envelope; reject.
            continue;
        }

        // Policy checks the mainline TransactionQueue ran outside of
        // checkValid (see TransactionQueue::canAdd on master).
        if (protocolVersionIsBefore(lclVersion, ProtocolVersion::V_25) &&
            !tx->validateSorobanMemo())
        {
            continue;
        }
        if (!tx->validateHostFn())
        {
            continue;
        }

        // Chain support: when the tx's seqnum is within the allowed gap
        // ahead of the account's current seqnum, substitute `current` so the
        // strict seqnum-equality check passes while every other check
        // (signatures, fees, balance, preconditions) still runs. Stale or
        // too-far-future seqnums keep current=0 and fail checkValid's strict
        // check as usual.
        SequenceNumber current = 0;
        auto sourceAccount = chunkView.getAccount(tx->getSourceID());
        if (sourceAccount)
        {
            auto acctSeq = sourceAccount.current().data.account().seqNum;
            auto txSeq = tx->getSeqNum();
            if (txSeq > acctSeq && txSeq - acctSeq <= MAX_SEQ_GAP_FOR_FLOODING)
            {
                current = txSeq - 1;
            }
        }

        auto result =
            tx->checkValidForOverlay(app.getAppConnector(), chunkView, current,
                                     0, batch->mUpperBoundCloseTimeOffset,
                                     diagnostics, batch->mValidationLedgerSeq);
        batch->mVerdicts[i] = result->isSuccess() ? 1 : 0;
        if (!result->isSuccess())
        {
            CLOG_DEBUG(Herder, "Pre-flood validation rejected tx {} (code {})",
                       hexAbbrev(tx->getFullHash()),
                       static_cast<int>(result->getResultCode()));
        }
    }
}

} // namespace

void
validateTxBatchForFlooding(
    Application& app,
    std::shared_ptr<std::vector<TransactionEnvelope> const> envelopes,
    TxFloodVerdictCallback callback)
{
    releaseAssert(envelopes);
    if (envelopes->empty())
    {
        callback(TxFloodVerdicts{});
        return;
    }

    // The snapshot copy must happen on a registered non-apply thread
    // (threadIsType aborts on unregistered threads, and IPC reader threads
    // are unregistered), so the coordinator itself runs on the pool.
    app.postOnTxValidationThread(
        [&app, envelopes = std::move(envelopes),
         callback = std::move(callback)]() mutable {
            ZoneScoped;
            auto batch = std::make_shared<Batch>(
                app, std::move(envelopes), std::move(callback),
                app.getLedgerManager().copyImmutableLedgerView());

            size_t count = batch->mEnvelopes->size();
            size_t numThreads =
                std::max<size_t>(1, app.getTxValidationThreadCount());
            // The coordinator thread processes the first chunk itself, so
            // fan out at most (pool size) chunks total.
            size_t numChunks = std::min(numThreads, count);
            size_t chunkSize = count / numChunks;
            size_t remainder = count % numChunks;
            batch->mTasksRemaining.store(numChunks);

            auto finishTask = [batch]() {
                if (batch->mTasksRemaining.fetch_sub(1) == 1)
                {
                    batch->mCallback(batch->mVerdicts);
                }
            };

            size_t start = 0;
            std::vector<std::pair<size_t, size_t>> chunks;
            for (size_t i = 0; i < numChunks; ++i)
            {
                size_t end = start + chunkSize + (i < remainder ? 1 : 0);
                chunks.emplace_back(start, end);
                start = end;
            }
            // Post all chunks but the first; run the first inline.
            for (size_t i = 1; i < chunks.size(); ++i)
            {
                auto [begin, end] = chunks[i];
                app.postOnTxValidationThread(
                    [batch, begin, end, finishTask]() {
                        validateChunk(batch, begin, end);
                        finishTask();
                    },
                    "tx flood validation chunk");
            }
            validateChunk(batch, chunks[0].first, chunks[0].second);
            finishTask();
        },
        "tx flood validation batch");
}

} // namespace stellar
