// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "herder/TxSetFrame.h"
#include "ledger/LedgerHashUtils.h"
#include "transactions/TransactionFrameBase.h"
#include "util/UnorderedMap.h"
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <vector>

namespace stellar
{

// Streaming candidate-proposal builder (docs/direct-leader-flooding.md).
//
// Accumulates transaction frames as they clear the pre-flood validation gate
// so that a candidate leader can snapshot a proposal without re-fetching the
// mempool over IPC or re-decoding and re-hashing every envelope at trigger
// time. This is the C++ mirror of the slice of the Rust overlay mempool that
// matters for proposing, held as validated frames instead of wire bytes.
//
// The builder deliberately over-collects (capacity is a multiple of ledger
// capacity, mirroring the old 2x mempool over-fetch) and defers exact
// selection to makeTxSetFromTransactions: trimInvalid remains the strict
// per-account sequencing and fee-coverage gate, exactly as for a
// mempool-fetched candidate list. Same-source transactions are kept as
// sequence-ordered chains so eviction never strands a successor whose
// predecessor was dropped.
//
// Thread-safety: insertions arrive from tx-validation pool threads (gate
// verdict callbacks) and the main thread (local submissions); removal,
// capacity updates, and snapshots run on the main thread. All state is
// guarded by a single mutex, and nothing under the lock touches ledger state
// or other locks.
class TxProposalBuilder
{
  public:
    // Age after which an unproposed transaction is dropped; mirrors the Rust
    // overlay mempool's max_age.
    static std::chrono::seconds const MAX_TX_AGE;

    TxProposalBuilder();

    // Only validators build proposals; on other nodes the builder stays
    // disabled and addTransaction is a no-op.
    void setEnabled(bool enabled);

    // Add a gate-validated transaction. Duplicates (by full hash) are
    // ignored. A second transaction with the same (source account, seqnum)
    // replaces the first only with a strictly higher inclusion fee rate.
    // Callable from any thread.
    void addTransaction(TransactionFrameBasePtr const& tx);

    // Drop the given transactions, e.g. because they were externalized in a
    // ledger or found invalid by trimInvalid. Callable from any thread.
    void removeTransactions(std::vector<Hash> const& hashes);

    // Update the capacity to `maxTxs` transactions and sweep out entries
    // older than MAX_TX_AGE. When over capacity, the lowest-fee-rate
    // transaction is evicted together with its same-account successors (a
    // chain tail). Called on ledger close from the main thread; insertions
    // use the last value set here.
    void setCapacityAndSweep(size_t maxTxs);

    // Snapshot the current candidates: per-account chains flattened in
    // sequence-number order, split into classic and Soroban lists.
    void snapshot(TxFrameList& classicTxs, TxFrameList& sorobanTxs) const;

    size_t size() const;

  private:
    struct Entry
    {
        TransactionFrameBasePtr mTx;
        std::chrono::steady_clock::time_point mAdded;
    };
    // Ordered per-account chain: seqnum -> entry.
    using AccountChain = std::map<SequenceNumber, Entry>;

    // Ascending inclusion-fee-rate order; begin() is the eviction candidate.
    struct FeeOrder
    {
        int64_t mFee;
        uint32_t mOps;
        Hash mHash;
    };
    struct FeeOrderLess
    {
        bool operator()(FeeOrder const& a, FeeOrder const& b) const;
    };

    // All private helpers require mMutex to be held. `hash` is taken by
    // value: callers pass references into the very entry being erased (e.g.
    // the incumbent's own getFullHash() during same-seq replacement), which
    // would dangle mid-erase if bound by reference.
    bool eraseLocked(Hash hash);
    void evictChainTailLocked();
    void enforceCapacityLocked();

    mutable std::mutex mMutex;
    bool mEnabled{false};
    size_t mMaxTxs;
    UnorderedMap<Hash, std::pair<AccountID, SequenceNumber>> mByHash;
    UnorderedMap<AccountID, AccountChain> mByAccount;
    std::set<FeeOrder, FeeOrderLess> mByFeeRate;
};

} // namespace stellar
