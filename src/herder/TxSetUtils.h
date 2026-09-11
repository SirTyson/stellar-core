// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/TxSetFrame.h"
#include "util/UnorderedMap.h"
#include "xdr/Stellar-types.h"
#include <ledger/LedgerHashUtils.h>
#include <tuple>

namespace stellar
{

// Information about invalid transactions in a tx set and the aggregate
// validation result for that set.
using TxFrameListWithErrors = std::pair<TxFrameList, TxSetValidationResult>;

// Validation state for one Soroban nomination, against one immutable ledger.
// Validates requested candidates in parallel and remembers the results across
// refills. Shared fee payers retain trimInvalid's aggregate affordability
// policy, including fees already examined in the Classic phase.
class TxSetCandidateValidator
{
  public:
    TxSetCandidateValidator(TxFrameList const& candidates, Application& app,
                            UnorderedMap<AccountID, int64_t> const& priorFees,
                            uint64_t lowerBoundCloseTimeOffset,
                            uint64_t upperBoundCloseTimeOffset);

    void validate(TxFrameList const& candidates);
    bool isChecked(TransactionFrameBasePtr const& tx) const;
    bool isValid(TransactionFrameBasePtr const& tx) const;
    bool isInvalid(TransactionFrameBasePtr const& tx) const;

  private:
    struct FeeSource
    {
        TxFrameList candidates;
        int64_t priorFees{0};
        int64_t maximumFees{0};
        std::optional<int64_t> availableBalance;
        bool resolved{false};
        bool affordable{false};
    };

    void checkTransactions(TxFrameList const& candidates);

    Application& mApp;
    uint64_t mLowerBoundCloseTimeOffset;
    uint64_t mUpperBoundCloseTimeOffset;
    UnorderedMap<AccountID, FeeSource> mFeeSources;
    UnorderedMap<TransactionFrameBasePtr, bool> mIndividualValidity;
};

class AccountTransactionQueue
{
  public:
    AccountTransactionQueue(
        std::vector<TransactionFrameBasePtr> const& accountTxs);

    TransactionFrameBasePtr getTopTx() const;
    bool empty() const;
    void popTopTx();

  private:
    std::deque<TransactionFrameBasePtr> mTxs;
    uint32_t mNumOperations = 0;
};

class TxSetUtils
{
  public:
    static bool hashTxSorter(TransactionFrameBasePtr const& tx1,
                             TransactionFrameBasePtr const& tx2);

    static TxFrameList sortTxsInHashOrder(TxFrameList const& transactions);
    static TxStageFrameList
    sortParallelTxsInHashOrder(TxStageFrameList const& stages);

    static std::vector<std::shared_ptr<AccountTransactionQueue>>
    buildAccountTxQueues(TxFrameList const& txs);

    // Returns transactions from a TxSet that are invalid along with the
    // aggregate validation result for the set.
    template <typename TxContainer>
    static TxFrameListWithErrors
    getInvalidTxListWithErrors(TxContainer const& txs, Application& app,
                               UnorderedMap<AccountID, int64_t>& accountFeeMap,
                               uint64_t lowerBoundCloseTimeOffset,
                               uint64_t upperBoundCloseTimeOffset);

    static TxFrameList
    trimInvalid(TxFrameList const& txs, Application& app,
                UnorderedMap<AccountID, int64_t>& accountFeeMap,
                uint64_t lowerBoundCloseTimeOffset,
                uint64_t upperBoundCloseTimeOffset, TxFrameList& invalidTxs);
}; // class TxSetUtils
} // namespace stellar
