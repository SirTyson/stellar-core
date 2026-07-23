// Copyright 2022 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/TxSetFrame.h"
#include "util/GlobalChecks.h"
#include "util/UnorderedMap.h"
#include "xdr/Stellar-types.h"
#include <ledger/LedgerHashUtils.h>
#include <tuple>

namespace stellar
{

// Information about invalid transactions in a tx set and the aggregate
// validation result for that set.
using TxFrameListWithErrors = std::pair<TxFrameList, TxSetValidationResult>;

// Transaction frames pre-constructed (and pre-hashed) on the tx-validation
// pool in the exact wire order of a tx set, consumed sequentially while
// re-walking the same XDR on the calling thread.
class PrebuiltTxFrames
{
    TxFrameList mFrames;
    size_t mNext{0};

  public:
    explicit PrebuiltTxFrames(TxFrameList&& frames) : mFrames(std::move(frames))
    {
    }
    TransactionFrameBasePtr
    next()
    {
        releaseAssert(mNext < mFrames.size());
        return mFrames[mNext++];
    }
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
#ifdef BUILD_TESTS
    // Test hook: force the serial validation/construction paths so tests can
    // compare parallel and serial results on identical inputs.
    static bool gForceSerialValidation;
#endif

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

    // Constructs tx frames from wire envelopes (XDR decode plus hash
    // computation, both per-tx independent) on the tx-validation pool,
    // returning them in input order. Falls back to serial construction for
    // small inputs. The returned frames have their hashes pre-computed.
    static TxFrameList buildTxFramesParallel(
        Hash const& networkID,
        std::vector<TransactionEnvelope const*> const& envelopes,
        Application& app);

    static TxFrameList
    trimInvalid(TxFrameList const& txs, Application& app,
                UnorderedMap<AccountID, int64_t>& accountFeeMap,
                uint64_t lowerBoundCloseTimeOffset,
                uint64_t upperBoundCloseTimeOffset, TxFrameList& invalidTxs);
}; // class TxSetUtils
} // namespace stellar
