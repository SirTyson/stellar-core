// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/asio.h"
#include "TxSetUtils.h"
#include "crypto/Hex.h"
#include "crypto/Random.h"
#include "crypto/SHA.h"
#include "database/Database.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/ErrorMessages.h"
#include "transactions/MutableTransactionResult.h"
#include "transactions/TransactionUtils.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/ProtocolVersion.h"
#include "util/UnorderedSet.h"
#include "util/XDRCereal.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"

#include <Tracy.hpp>
#include <algorithm>
#include <future>
#include <list>
#include <numeric>

namespace stellar
{

#ifdef BUILD_TESTS
bool TxSetUtils::gForceSerialValidation = false;
#endif

namespace
{
// Target use case is to remove a subset of invalid transactions from a TxSet.
// I.e. txSet.size() >= txsToRemove.size()
TxFrameList
removeTxs(TxFrameList const& txs, TxFrameList const& txsToRemove)
{
    UnorderedSet<Hash> txsToRemoveSet;
    txsToRemoveSet.reserve(txsToRemove.size());
    std::transform(
        txsToRemove.cbegin(), txsToRemove.cend(),
        std::inserter(txsToRemoveSet, txsToRemoveSet.end()),
        [](TransactionFrameBasePtr const& tx) { return tx->getFullHash(); });

    TxFrameList newTxs;
    newTxs.reserve(txs.size() - txsToRemove.size());
    for (auto const& tx : txs)
    {
        if (txsToRemoveSet.find(tx->getFullHash()) == txsToRemoveSet.end())
        {
            newTxs.emplace_back(tx);
        }
    }

    return newTxs;
}
} // namespace

AccountTransactionQueue::AccountTransactionQueue(
    std::vector<TransactionFrameBasePtr> const& accountTxs)
    : mTxs(accountTxs.begin(), accountTxs.end())
{
    releaseAssert(!mTxs.empty());
    std::sort(mTxs.begin(), mTxs.end(),
              [](TransactionFrameBasePtr const& tx1,
                 TransactionFrameBasePtr const& tx2) {
                  return tx1->getSeqNum() < tx2->getSeqNum();
              });
    for (auto const& tx : accountTxs)
    {
        mNumOperations += tx->getNumOperations();
    }
}

TransactionFrameBasePtr
AccountTransactionQueue::getTopTx() const
{
    releaseAssert(!mTxs.empty());
    return mTxs.front();
}

bool
AccountTransactionQueue::empty() const
{
    return mTxs.empty();
}

void
AccountTransactionQueue::popTopTx()
{
    releaseAssert(!mTxs.empty());
    mNumOperations -= mTxs.front()->getNumOperations();
    mTxs.pop_front();
}

bool
TxSetUtils::hashTxSorter(TransactionFrameBasePtr const& tx1,
                         TransactionFrameBasePtr const& tx2)
{
    // need to use the hash of whole tx here since multiple txs could have
    // the same Contents
    return tx1->getFullHash() < tx2->getFullHash();
}

TxFrameList
TxSetUtils::sortTxsInHashOrder(TxFrameList const& transactions)
{
    ZoneScoped;
    TxFrameList sortedTxs(transactions);
    std::sort(sortedTxs.begin(), sortedTxs.end(), TxSetUtils::hashTxSorter);
    return sortedTxs;
}

TxStageFrameList
TxSetUtils::sortParallelTxsInHashOrder(TxStageFrameList const& stages)
{
    ZoneScoped;
    TxStageFrameList sortedStages = stages;
    for (auto& stage : sortedStages)
    {
        for (auto& thread : stage)
        {
            std::sort(thread.begin(), thread.end(), TxSetUtils::hashTxSorter);
        }
        std::sort(stage.begin(), stage.end(), [](auto const& a, auto const& b) {
            releaseAssert(!a.empty() && !b.empty());
            return hashTxSorter(a.front(), b.front());
        });
    }
    std::sort(sortedStages.begin(), sortedStages.end(),
              [](auto const& a, auto const& b) {
                  releaseAssert(!a.empty() && !b.empty());
                  releaseAssert(!a.front().empty() && !b.front().empty());
                  return hashTxSorter(a.front().front(), b.front().front());
              });
    return sortedStages;
}

std::vector<std::shared_ptr<AccountTransactionQueue>>
TxSetUtils::buildAccountTxQueues(TxFrameList const& txs)
{
    ZoneScoped;
    UnorderedMap<AccountID, std::vector<TransactionFrameBasePtr>> actTxMap;

    for (auto const& tx : txs)
    {
        auto id = tx->getSourceID();
        auto it =
            actTxMap.emplace(id, std::vector<TransactionFrameBasePtr>()).first;
        it->second.emplace_back(tx);
    }

    std::vector<std::shared_ptr<AccountTransactionQueue>> queues;
    for (auto const& [_, actTxs] : actTxMap)
    {
        queues.emplace_back(std::make_shared<AccountTransactionQueue>(actTxs));
    }
    return queues;
}

namespace
{

// Minimum number of transactions for which the parallel validation fan-out is
// worth the fork-join overhead; smaller lists validate serially.
constexpr size_t MIN_TXS_FOR_PARALLEL_VALIDATION = 32;

// Run `tasks` on the tx-validation pool and block until all complete.
// Exceptions are rethrown on the calling thread, lowest task index first, so
// failure behavior is deterministic regardless of scheduling.
void
runOnTxValidationPoolAndJoin(Application& app,
                             std::vector<std::function<void()>>&& tasks)
{
    std::vector<std::future<void>> futures;
    futures.reserve(tasks.size());
    std::exception_ptr postException;
    for (auto& task : tasks)
    {
        auto packaged =
            std::make_shared<std::packaged_task<void()>>(std::move(task));
        auto future = packaged->get_future();
        try
        {
            app.postOnTxValidationThread([packaged]() { (*packaged)(); },
                                         "parallel tx validation");
            futures.emplace_back(std::move(future));
        }
        catch (...)
        {
            postException = std::current_exception();
            break;
        }
    }

    // Always observe every future before rethrowing. Otherwise an early
    // exception would unwind while later chunks still reference the caller's
    // stack (including txValid and the base snapshot).
    std::exception_ptr firstException;
    for (auto& future : futures)
    {
        try
        {
            future.get();
        }
        catch (...)
        {
            if (!firstException)
            {
                firstException = std::current_exception();
            }
        }
    }
    if (firstException)
    {
        std::rethrow_exception(firstException);
    }
    if (postException)
    {
        std::rethrow_exception(postException);
    }
}

// Split [0, count) into contiguous chunks sized for the validation pool:
// enough chunks to balance uneven per-tx costs (Soroban vs classic), but
// never so many that per-chunk setup (a ledger view copy, ~100us) dominates.
std::vector<std::pair<size_t, size_t>>
makeValidationChunks(size_t count, size_t numThreads)
{
    constexpr size_t chunksPerThread = 2;
    constexpr size_t minChunkSize = 8;
    size_t numChunks =
        std::min(std::max<size_t>(1, count / minChunkSize),
                 std::max<size_t>(1, numThreads * chunksPerThread));
    std::vector<std::pair<size_t, size_t>> chunks;
    chunks.reserve(numChunks);
    size_t chunkSize = count / numChunks;
    size_t remainder = count % numChunks;
    size_t start = 0;
    for (size_t i = 0; i < numChunks; ++i)
    {
        size_t end = start + chunkSize + (i < remainder ? 1 : 0);
        chunks.emplace_back(start, end);
        start = end;
    }
    return chunks;
}

} // namespace

template <typename T>
TxFrameListWithErrors
TxSetUtils::getInvalidTxListWithErrors(
    T const& txs, Application& app,
    UnorderedMap<AccountID, int64_t>& accountFeeMap,
    uint64_t lowerBoundCloseTimeOffset, uint64_t upperBoundCloseTimeOffset)
{
    ZoneScoped;
    releaseAssert(threadIsMain());

    // Materialize the container for stable per-index access across threads
    // (T may be a phase frame with a flattening iterator).
    std::vector<TransactionFrameBasePtr> flatTxs;
    for (auto const& tx : txs)
    {
        flatTxs.push_back(tx);
    }

    bool skipSeqNumCheck = false;
#ifdef BUILD_TESTS
    // See TransactionQueue::canAdd for the overlay-only-mode rationale.
    skipSeqNumCheck = app.getRunInOverlayOnlyMode();
#endif

    bool useParallel = flatTxs.size() >= MIN_TXS_FOR_PARALLEL_VALIDATION &&
                       app.getTxValidationThreadCount() > 0;
#ifdef BUILD_TESTS
    // The in-memory-ledger test mode has no bucket list snapshot to copy, so
    // it must use the (main-thread-only) legacy LedgerTxn-backed view.
    useParallel = useParallel && !app.getConfig().MODE_USES_IN_MEMORY_LEDGER &&
                  !gForceSerialValidation;
#endif

    if (useParallel)
    {
        // The public helper can be called directly with the same frame object
        // more than once. Fall back to serial in that adversarial case: lazy
        // frame memoization is not synchronized, even though distinct frames
        // reconstructed from an identical envelope are safe to validate in
        // parallel and retain the duplicate-full-hash semantics below.
        // Production frame construction also gives every fee-bump frame its
        // own inner frame; distinct top-level frames must not alias an inner
        // TransactionFramePtr.
        std::unordered_set<TransactionFrameBase const*> frames;
        frames.reserve(flatTxs.size());
        for (auto const& tx : flatTxs)
        {
            if (!frames.emplace(tx.get()).second)
            {
                useParallel = false;
                break;
            }
        }
    }

    // checkValid mutates per-frame lazy state (cached hashes and, for fee
    // bumps, the inner frame), so each frame is validated by exactly one
    // thread. Each chunk also gets its own view copy because views own
    // per-instance file streams. The _DEBUG contents-hash swap is safe under
    // the same one-frame-one-thread invariant.
    std::vector<uint8_t> txValid(flatTxs.size(), 0);
    std::optional<ImmutableLedgerView> baseView;
    std::unique_ptr<CheckValidLedgerViewWrapper> serialLedgerView;

    // Validate minSeqLedgerGap and LedgerBounds against the next ledgerSeq,
    // which is what will be used at apply time.
    std::optional<uint32_t> validationLedgerSeq;
    auto computeValidationLedgerSeq = [&](LedgerHeader const& lclHeader) {
        if (protocolVersionStartsFrom(lclHeader.ledgerVersion,
                                      ProtocolVersion::V_19))
        {
            validationLedgerSeq =
                app.getLedgerManager().getLastClosedLedgerNum() + 1;
        }
    };

    // Pass 1: per-tx checkValid. Each tx is validated independently against
    // the same LCL snapshot (current=0 reads sequence numbers directly from
    // ledger state, so there is no cross-tx sequencing here). checkValid never
    // reads accountFeeMap, which is only in a defined state on normal return;
    // both callers own it locally and discard it if validation throws.
    if (useParallel)
    {
        baseView.emplace(app.getLedgerManager().copyImmutableLedgerView());
        auto header = baseView->getLedgerHeader().current();
        computeValidationLedgerSeq(header);

        auto validateChunk = [&](size_t begin, size_t end) {
            CheckValidLedgerViewWrapper chunkView(*baseView);
#ifdef BUILD_TESTS
            chunkView.mSkipSeqNumCheck = skipSeqNumCheck;
#endif
            auto diagnostics = DiagnosticEventManager::createDisabled();
            for (size_t i = begin; i < end; ++i)
            {
                auto txResult = flatTxs[i]->checkValid(
                    app.getAppConnector(), chunkView, 0,
                    lowerBoundCloseTimeOffset, upperBoundCloseTimeOffset,
                    diagnostics, validationLedgerSeq);
                txValid[i] = txResult->isSuccess() ? 1 : 0;
            }
        };

        auto chunks = makeValidationChunks(flatTxs.size(),
                                           app.getTxValidationThreadCount());
        std::vector<std::function<void()>> tasks;
        tasks.reserve(chunks.size());
        for (auto const& [begin, end] : chunks)
        {
            tasks.emplace_back([&validateChunk, begin, end]() {
                validateChunk(begin, end);
            });
        }
        runOnTxValidationPoolAndJoin(app, std::move(tasks));
    }
    else
    {
        serialLedgerView =
            std::make_unique<CheckValidLedgerViewWrapper>(app);
#ifdef BUILD_TESTS
        serialLedgerView->mSkipSeqNumCheck = skipSeqNumCheck;
#endif
        auto header = serialLedgerView->getLedgerHeader().current();
        computeValidationLedgerSeq(header);
        auto diagnostics = DiagnosticEventManager::createDisabled();
        for (size_t i = 0; i < flatTxs.size(); ++i)
        {
            auto txResult = flatTxs[i]->checkValid(
                app.getAppConnector(), *serialLedgerView, 0,
                lowerBoundCloseTimeOffset, upperBoundCloseTimeOffset,
                diagnostics, validationLedgerSeq);
            txValid[i] = txResult->isSuccess() ? 1 : 0;
        }
    }

    TxFrameListWithErrors invalidTxsWithError;
    auto& invalidTxs = invalidTxsWithError.first;
    auto& errorCode = invalidTxsWithError.second;
    errorCode = TxSetValidationResult::VALID;

    std::unordered_set<Hash> seenInvalidTxs;
    // Reduce pass 1 on the main thread in input order, preserving invalid-list
    // order and error-code precedence exactly.
    for (size_t i = 0; i < flatTxs.size(); ++i)
    {
        auto const& tx = flatTxs[i];
        if (!txValid[i])
        {
            invalidTxs.emplace_back(tx);
            seenInvalidTxs.emplace(tx->getFullHash());
            errorCode = TxSetValidationResult::TX_VALIDATION_FAILED;
        }
        else
        {
            // All admitted addends are nonnegative (classic fees are uint32;
            // fee-bump XDRProvidesValidFee rejects negative fees), so this
            // saturating sum is order-independent even with pre-seeded values.
            int64_t& accFee = accountFeeMap[tx->getFeeSourceID()];
            if (INT64_MAX - accFee < tx->getFullFee())
            {
                accFee = INT64_MAX;
            }
            else
            {
                accFee += tx->getFullFee();
            }
        }
    }

    // Pass 2 deliberately remains serial and hash-gated. The evolving hash set
    // suppresses later duplicates, so only the first unaffordable transaction
    // with a given full hash is appended.
    auto runPass2 = [&](CheckValidLedgerViewWrapper const& ledgerView) {
        auto header = ledgerView.getLedgerHeader().current();
        for (auto const& tx : txs)
        {
            // Already added invalid tx
            if (seenInvalidTxs.find(tx->getFullHash()) != seenInvalidTxs.end())
            {
                continue;
            }

            auto feeSourceID = tx->getFeeSourceID();
            auto feeSource = ledgerView.getAccount(feeSourceID);
            // feeSource should exist since we've already run checkValid, log
            // internal bug
            if (!feeSource)
            {
                CLOG_ERROR(Herder,
                           "Account not found when checking TxSet validity");
                CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
                continue;
            }
            auto it = accountFeeMap.find(feeSourceID);
            auto totFee = it->second;
            if (getAvailableBalance(header, feeSource.current()) < totFee)
            {
                invalidTxs.push_back(tx);
                // Only override the error code if it wasn't already set
                if (errorCode == TxSetValidationResult::VALID)
                {
                    errorCode = TxSetValidationResult::ACCOUNT_CANT_PAY_FEE;
                }
                releaseAssert(seenInvalidTxs.insert(tx->getFullHash()).second);
                CLOG_DEBUG(
                    Herder, "Got bad txSet: account can't pay fee tx: {}",
                    xdrToCerealString(tx->getEnvelope(), "TransactionEnvelope"));
            }
        }
    };

    if (useParallel)
    {
        // Chunk views are gone after the join; pass 2 gets a fresh wrapper over
        // the exact same pinned snapshot.
        CheckValidLedgerViewWrapper pass2View(*baseView);
#ifdef BUILD_TESTS
        pass2View.mSkipSeqNumCheck = skipSeqNumCheck;
#endif
        runPass2(pass2View);
    }
    else
    {
        runPass2(*serialLedgerView);
    }

    return invalidTxsWithError;
}

// Explicit template instantiations for getInvalidTxListWithErrors
template TxFrameListWithErrors
TxSetUtils::getInvalidTxListWithErrors<TxFrameList>(
    TxFrameList const& txs, Application& app,
    UnorderedMap<AccountID, int64_t>& accountFeeMap,
    uint64_t lowerBoundCloseTimeOffset, uint64_t upperBoundCloseTimeOffset);
template TxFrameListWithErrors
TxSetUtils::getInvalidTxListWithErrors<TxSetPhaseFrame>(
    TxSetPhaseFrame const& txs, Application& app,
    UnorderedMap<AccountID, int64_t>& accountFeeMap,
    uint64_t lowerBoundCloseTimeOffset, uint64_t upperBoundCloseTimeOffset);

TxFrameList
TxSetUtils::trimInvalid(TxFrameList const& txs, Application& app,
                        UnorderedMap<AccountID, int64_t>& accountFeeMap,
                        uint64_t lowerBoundCloseTimeOffset,
                        uint64_t upperBoundCloseTimeOffset,
                        TxFrameList& invalidTxs)
{
    invalidTxs = getInvalidTxListWithErrors(txs, app, accountFeeMap,
                                            lowerBoundCloseTimeOffset,
                                            upperBoundCloseTimeOffset)
                     .first;
    return removeTxs(txs, invalidTxs);
}

} // namespace stellar
