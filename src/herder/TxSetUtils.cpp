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
#include "herder/SurgePricingUtils.h"
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
#include <limits>
#include <list>
#include <numeric>

namespace stellar
{
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

template <typename T>
TxFrameListWithErrors
TxSetUtils::getInvalidTxListWithErrors(
    T const& txs, Application& app,
    UnorderedMap<AccountID, int64_t>& accountFeeMap,
    uint64_t lowerBoundCloseTimeOffset, uint64_t upperBoundCloseTimeOffset)
{
    ZoneScoped;
    releaseAssert(threadIsMain());
    CheckValidLedgerViewWrapper ledgerView(app);
#ifdef BUILD_TESTS
    // See TransactionQueue::canAdd for the overlay-only-mode rationale.
    ledgerView.mSkipSeqNumCheck = app.getRunInOverlayOnlyMode();
#endif
    // Validate minSeqLedgerGap and LedgerBounds against the next ledgerSeq,
    // which is what will be used at apply time.
    std::optional<uint32_t> validationLedgerSeq;
    if (protocolVersionStartsFrom(
            ledgerView.getLedgerHeader().current().ledgerVersion,
            ProtocolVersion::V_19))
    {
        validationLedgerSeq =
            app.getLedgerManager().getLastClosedLedgerNum() + 1;
    }

    TxFrameListWithErrors invalidTxsWithError;
    auto& invalidTxs = invalidTxsWithError.first;
    auto& errorCode = invalidTxsWithError.second;
    errorCode = TxSetValidationResult::VALID;

    std::unordered_set<Hash> seenInvalidTxs;
    auto diagnostics = DiagnosticEventManager::createDisabled();
    for (auto const& tx : txs)
    {
        auto txResult = tx->checkValid(
            app.getAppConnector(), ledgerView, 0, lowerBoundCloseTimeOffset,
            upperBoundCloseTimeOffset, diagnostics, validationLedgerSeq);
        if (!txResult->isSuccess())
        {
            invalidTxs.emplace_back(tx);
            seenInvalidTxs.emplace(tx->getFullHash());
            errorCode = TxSetValidationResult::TX_VALIDATION_FAILED;
        }
        else
        {
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
    // Validate and reserve fees one transaction at a time, in the same
    // highest-inclusion-fee-rate order used by surge pricing. The validation
    // routine deliberately rejects an externally supplied set when the
    // aggregate fees exceed a fee source's available balance. During local
    // construction, however, marking every individually-valid transaction
    // from that fee source invalid would produce an empty proposal forever.
    // Incremental reservation keeps the highest-priority affordable subset
    // and reports only the remainder as invalid/deferred.
    TxFrameList priorityOrder = txs;
    std::sort(priorityOrder.begin(), priorityOrder.end(),
              TxFeeComparator(/*isGreater=*/true,
                              rand_uniform<size_t>(
                                  0, std::numeric_limits<size_t>::max())));

    UnorderedSet<Hash> selected;
    selected.reserve(txs.size());
    invalidTxs.clear();
    auto reservedFees = accountFeeMap;
    for (auto const& tx : priorityOrder)
    {
        auto feesIfIncluded = reservedFees;
        TxFrameList one{tx};
        auto invalid = getInvalidTxListWithErrors(
                           one, app, feesIfIncluded,
                           lowerBoundCloseTimeOffset,
                           upperBoundCloseTimeOffset)
                           .first;
        if (invalid.empty())
        {
            selected.emplace(tx->getFullHash());
            reservedFees = std::move(feesIfIncluded);
        }
        else
        {
            invalidTxs.emplace_back(tx);
        }
    }
    accountFeeMap = std::move(reservedFees);

    TxFrameList valid;
    valid.reserve(selected.size());
    for (auto const& tx : txs)
    {
        if (selected.count(tx->getFullHash()) != 0)
        {
            valid.emplace_back(tx);
        }
    }
    return valid;
}

TxSetUtils::TxSetCandidates
TxSetUtils::selectTxSetCandidates(TxFrameList const& candidates,
                                  bool supportsSoroban,
                                  AccountSeqLookup const& seqOf)
{
    ZoneScoped;
    TxSetCandidates res;
    res.phases.resize(supportsSoroban ? 2 : 1);

    // Account sequence numbers are looked up once per account.
    UnorderedMap<AccountID, std::optional<SequenceNumber>> accountSeqs;
    // Index (into `candidates`) of the best candidate seen so far for each
    // source account.
    UnorderedMap<AccountID, size_t> bestBySource;

    for (size_t i = 0; i < candidates.size(); ++i)
    {
        auto const& tx = candidates[i];
        if (tx->isSoroban() && !supportsSoroban)
        {
            // Not applicable yet; leave it in the mempool for after the
            // protocol upgrade.
            continue;
        }
        auto const source = tx->getSourceID();
        auto [seqIt, firstSeen] = accountSeqs.try_emplace(source, std::nullopt);
        if (firstSeen)
        {
            seqIt->second = seqOf(source);
        }
        auto const& accountSeq = seqIt->second;
        if (!accountSeq || tx->getSeqNum() <= *accountSeq)
        {
            // No such account, or the sequence number has already been
            // consumed: this can never apply.
            res.toRemove.push_back(tx->getFullHash());
            continue;
        }
        // From here on accountSeq < seq, so the lowest sequence number among
        // an account's candidates is accountSeq + 1 whenever such a candidate
        // exists; otherwise it is the first chained tx. On ties the earlier
        // candidate (better fee rate) wins.
        auto [bestIt, isFirst] = bestBySource.try_emplace(source, i);
        if (!isFirst &&
            tx->getSeqNum() < candidates[bestIt->second]->getSeqNum())
        {
            bestIt->second = i;
        }
    }
    res.numSourceAccounts = accountSeqs.size();

    // Emit the winners in candidate (fee) order.
    for (size_t i = 0; i < candidates.size(); ++i)
    {
        auto const& tx = candidates[i];
        auto it = bestBySource.find(tx->getSourceID());
        if (it == bestBySource.end() || it->second != i)
        {
            continue;
        }
        auto phase = static_cast<size_t>(tx->isSoroban() ? TxSetPhase::SOROBAN
                                                         : TxSetPhase::CLASSIC);
        res.phases[phase].push_back(tx);
    }
    return res;
}

bool
TxSetUtils::isTransientValidationFailure(
    TransactionResultCode code, SequenceNumber txSeq,
    std::optional<SequenceNumber> const& accountSeq)
{
    switch (code)
    {
    case txSUCCESS:
        // The tx itself is valid; it was only trimmed because its fee source
        // cannot pay for all of its pending txs at once.
    case txTOO_EARLY:
    case txBAD_MIN_SEQ_AGE_OR_GAP:
        return true;
    case txBAD_SEQ:
        // A chained tx whose predecessor has not applied yet.
        return accountSeq &&
               *accountSeq < std::numeric_limits<SequenceNumber>::max() &&
               txSeq > *accountSeq + 1;
    default:
        return false;
    }
}

std::vector<Hash>
TxSetUtils::permanentlyInvalidTxHashes(PerPhaseTransactionList const& invalid,
                                       TxResultCodeLookup const& codeOf,
                                       AccountSeqLookup const& seqOf)
{
    ZoneScoped;
    std::vector<Hash> res;
    UnorderedMap<AccountID, std::optional<SequenceNumber>> accountSeqs;
    for (auto const& phase : invalid)
    {
        for (auto const& tx : phase)
        {
            auto code = codeOf(tx);
            std::optional<SequenceNumber> accountSeq;
            if (code == txBAD_SEQ)
            {
                auto const source = tx->getSourceID();
                auto [it, firstSeen] =
                    accountSeqs.try_emplace(source, std::nullopt);
                if (firstSeen)
                {
                    it->second = seqOf(source);
                }
                accountSeq = it->second;
            }
            if (!isTransientValidationFailure(code, tx->getSeqNum(),
                                              accountSeq))
            {
                res.push_back(tx->getFullHash());
            }
        }
    }
    return res;
}

} // namespace stellar
