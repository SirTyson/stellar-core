// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/TxProposalBuilder.h"
#include "herder/SurgePricingUtils.h"
#include "util/GlobalChecks.h"

#include <Tracy.hpp>

namespace stellar
{

std::chrono::seconds const TxProposalBuilder::MAX_TX_AGE{300};

// Before the first ledger close supplies a real capacity, hold roughly what
// the Rust mempool would return for one over-fetched proposal.
static size_t constexpr DEFAULT_MAX_TXS = 20'000;

bool
TxProposalBuilder::FeeOrderLess::operator()(FeeOrder const& a,
                                            FeeOrder const& b) const
{
    int cmp = feeRate3WayCompare(a.mFee, a.mOps, b.mFee, b.mOps);
    if (cmp != 0)
    {
        return cmp < 0;
    }
    return a.mHash < b.mHash;
}

TxProposalBuilder::TxProposalBuilder() : mMaxTxs(DEFAULT_MAX_TXS)
{
}

void
TxProposalBuilder::setEnabled(bool enabled)
{
    std::lock_guard<std::mutex> guard(mMutex);
    mEnabled = enabled;
}

void
TxProposalBuilder::addTransaction(TransactionFrameBasePtr const& tx)
{
    ZoneScoped;
    releaseAssert(tx);
    auto const hash = tx->getFullHash();
    auto const acct = tx->getSourceID();
    auto const seq = tx->getSeqNum();
    auto const fee = tx->getInclusionFee();
    auto const ops = tx->getNumOperations();

    std::lock_guard<std::mutex> guard(mMutex);
    if (!mEnabled || mByHash.find(hash) != mByHash.end())
    {
        return;
    }

    {
        auto chainIt = mByAccount.find(acct);
        if (chainIt != mByAccount.end())
        {
            auto entryIt = chainIt->second.find(seq);
            if (entryIt != chainIt->second.end())
            {
                // Same (source account, seqnum): only a strictly higher
                // inclusion fee rate replaces the incumbent.
                auto const& cur = entryIt->second.mTx;
                if (feeRate3WayCompare(fee, ops, cur->getInclusionFee(),
                                       cur->getNumOperations()) <= 0)
                {
                    return;
                }
                eraseLocked(cur->getFullHash());
            }
        }
    }

    mByAccount[acct][seq] =
        Entry{tx, std::chrono::steady_clock::now()};
    mByHash.emplace(hash, std::make_pair(acct, seq));
    mByFeeRate.insert(FeeOrder{fee, ops, hash});

    enforceCapacityLocked();
}

void
TxProposalBuilder::removeTransactions(std::vector<Hash> const& hashes)
{
    ZoneScoped;
    std::lock_guard<std::mutex> guard(mMutex);
    for (auto const& hash : hashes)
    {
        eraseLocked(hash);
    }
}

void
TxProposalBuilder::setCapacityAndSweep(size_t maxTxs)
{
    ZoneScoped;
    std::lock_guard<std::mutex> guard(mMutex);
    mMaxTxs = maxTxs;

    auto const cutoff = std::chrono::steady_clock::now() - MAX_TX_AGE;
    std::vector<Hash> expired;
    for (auto const& [acct, chain] : mByAccount)
    {
        for (auto const& [seq, entry] : chain)
        {
            if (entry.mAdded < cutoff)
            {
                expired.push_back(entry.mTx->getFullHash());
            }
        }
    }
    for (auto const& hash : expired)
    {
        eraseLocked(hash);
    }

    enforceCapacityLocked();
}

void
TxProposalBuilder::snapshot(TxFrameList& classicTxs,
                            TxFrameList& sorobanTxs) const
{
    ZoneScoped;
    std::lock_guard<std::mutex> guard(mMutex);
    classicTxs.reserve(mByHash.size());
    for (auto const& [acct, chain] : mByAccount)
    {
        for (auto const& [seq, entry] : chain)
        {
            if (entry.mTx->isSoroban())
            {
                sorobanTxs.push_back(entry.mTx);
            }
            else
            {
                classicTxs.push_back(entry.mTx);
            }
        }
    }
}

size_t
TxProposalBuilder::size() const
{
    std::lock_guard<std::mutex> guard(mMutex);
    return mByHash.size();
}

bool
TxProposalBuilder::eraseLocked(Hash hash)
{
    auto it = mByHash.find(hash);
    if (it == mByHash.end())
    {
        return false;
    }
    auto const& [acct, seq] = it->second;

    auto chainIt = mByAccount.find(acct);
    releaseAssert(chainIt != mByAccount.end());
    auto entryIt = chainIt->second.find(seq);
    releaseAssert(entryIt != chainIt->second.end());
    auto const& tx = entryIt->second.mTx;

    mByFeeRate.erase(
        FeeOrder{tx->getInclusionFee(), tx->getNumOperations(), hash});
    chainIt->second.erase(entryIt);
    if (chainIt->second.empty())
    {
        mByAccount.erase(chainIt);
    }
    mByHash.erase(it);
    return true;
}

void
TxProposalBuilder::evictChainTailLocked()
{
    releaseAssert(!mByFeeRate.empty());
    auto const lowest = *mByFeeRate.begin();

    auto byHashIt = mByHash.find(lowest.mHash);
    releaseAssert(byHashIt != mByHash.end());
    auto const [acct, seq] = byHashIt->second;

    // The evicted tx's same-account successors are unusable without it (the
    // sequence chain breaks), so drop the whole tail.
    std::vector<Hash> tail;
    auto chainIt = mByAccount.find(acct);
    releaseAssert(chainIt != mByAccount.end());
    for (auto it = chainIt->second.lower_bound(seq);
         it != chainIt->second.end(); ++it)
    {
        tail.push_back(it->second.mTx->getFullHash());
    }
    for (auto const& hash : tail)
    {
        eraseLocked(hash);
    }
}

void
TxProposalBuilder::enforceCapacityLocked()
{
    while (mByHash.size() > mMaxTxs)
    {
        evictChainTailLocked();
    }
}

} // namespace stellar
