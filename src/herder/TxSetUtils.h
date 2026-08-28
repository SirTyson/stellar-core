// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/TxSetFrame.h"
#include "util/UnorderedMap.h"
#include "xdr/Stellar-types.h"
#include <functional>
#include <ledger/LedgerHashUtils.h>
#include <optional>
#include <tuple>

namespace stellar
{

// Information about invalid transactions in a tx set and the aggregate
// validation result for that set.
using TxFrameListWithErrors = std::pair<TxFrameList, TxSetValidationResult>;

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

    // ---- Mempool candidate selection (nomination) ----
    //
    // The overlay mempool is fee-ordered and may hand us several transactions
    // per source account (chained sequence numbers, same-seq competitors,
    // one classic and one Soroban tx, ...). A tx set may contain at most one
    // transaction per source account across all phases, so the candidates
    // have to be reduced before building the set. These helpers are pure
    // functions (ledger state is injected through lookups) so that they can
    // be unit-tested without an Application or an overlay process.

    // Returns the current sequence number of an account, or nullopt if the
    // account does not exist in the ledger view.
    using AccountSeqLookup =
        std::function<std::optional<SequenceNumber>(AccountID const&)>;

    struct TxSetCandidates
    {
        // phases[CLASSIC] always present, phases[SOROBAN] iff Soroban is
        // supported. At most one tx per source account across both phases,
        // in the same relative (fee) order as the input.
        PerPhaseTransactionList phases;
        // Hashes that can never become valid: stale sequence numbers
        // (seq <= account seq) and unknown source accounts. The caller is
        // expected to drop them from the mempool.
        std::vector<Hash> toRemove;
        // Number of distinct source accounts seen among the candidates.
        size_t numSourceAccounts{0};
    };

    // Selects at most one candidate per source account: the tx with
    // seq == accountSeq + 1 if there is one, otherwise the lowest seq greater
    // than the account seq (a chained tx whose predecessor may still be
    // pending; it fails validation later with txBAD_SEQ but must not be
    // removed). Ties (same account, same seq) keep the first candidate, i.e.
    // the one with the best fee rate. Soroban candidates are silently dropped
    // (not removed) when `supportsSoroban` is false.
    static TxSetCandidates
    selectTxSetCandidates(TxFrameList const& candidates, bool supportsSoroban,
                          AccountSeqLookup const& seqOf);

    using TxResultCodeLookup = std::function<TransactionResultCode(
        TransactionFrameBaseConstPtr const&)>;

    // Returns true if a validation failure with `code` may resolve on its own
    // in a later ledger, so the tx should stay in the mempool:
    // txTOO_EARLY, txBAD_MIN_SEQ_AGE_OR_GAP, txBAD_SEQ with a future sequence
    // number (seq > accountSeq + 1) and txSUCCESS (the tx was only trimmed by
    // the cumulative fee-source balance check).
    static bool isTransientValidationFailure(
        TransactionResultCode code, SequenceNumber txSeq,
        std::optional<SequenceNumber> const& accountSeq);

    // Given the per-phase lists of transactions that failed tx set
    // validation, returns the hashes of the ones that are permanently
    // invalid (see isTransientValidationFailure). `codeOf` yields the
    // validation result code of a tx, `seqOf` the source account sequence
    // number.
    static std::vector<Hash>
    permanentlyInvalidTxHashes(PerPhaseTransactionList const& invalid,
                               TxResultCodeLookup const& codeOf,
                               AccountSeqLookup const& seqOf);
}; // class TxSetUtils
} // namespace stellar
