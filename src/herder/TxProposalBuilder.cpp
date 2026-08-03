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
    if (!mEnabled)
    {
        return;
    }

    // A successful flood-gate verdict promotes a matching pre-verdict local
    // submission. Keep the frame built and validated by the gate, rather than
    // deduplicating against the unvalidated submit-path frame.
    eraseTentativeLocked(hash);
    if (mByHash.find(hash) != mByHash.end())
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
    enforceTentativeCapacityLocked();
}

void
TxProposalBuilder::addTentativeTransaction(TransactionFrameBasePtr const& tx)
{
    ZoneScoped;
    releaseAssert(tx);
    auto const hash = tx->getFullHash();
    auto const acct = tx->getSourceID();
    auto const seq = tx->getSeqNum();
    auto const fee = tx->getInclusionFee();
    auto const ops = tx->getNumOperations();

    std::lock_guard<std::mutex> guard(mMutex);
    if (!mEnabled || mByHash.find(hash) != mByHash.end() ||
        mTentativeByHash.find(hash) != mTentativeByHash.end())
    {
        return;
    }

    // A tentative transaction that cannot beat the validated incumbent is
    // never snapshot-selected and need not consume pre-verdict capacity.
    auto validatedChain = mByAccount.find(acct);
    if (validatedChain != mByAccount.end())
    {
        auto incumbent = validatedChain->second.find(seq);
        if (incumbent != validatedChain->second.end())
        {
            auto const& cur = incumbent->second.mTx;
            if (feeRate3WayCompare(fee, ops, cur->getInclusionFee(),
                                   cur->getNumOperations()) <= 0)
            {
                return;
            }
        }
    }

    // Keep at most the best tentative replacement for a source/sequence.
    auto tentativeChain = mTentativeByAccount.find(acct);
    if (tentativeChain != mTentativeByAccount.end())
    {
        auto incumbent = tentativeChain->second.find(seq);
        if (incumbent != tentativeChain->second.end())
        {
            auto const& cur = incumbent->second.mTx;
            if (feeRate3WayCompare(fee, ops, cur->getInclusionFee(),
                                   cur->getNumOperations()) <= 0)
            {
                return;
            }
            eraseTentativeLocked(cur->getFullHash());
        }
    }

    mTentativeByAccount[acct][seq] =
        Entry{tx, std::chrono::steady_clock::now()};
    mTentativeByHash.emplace(hash, std::make_pair(acct, seq));
    mTentativeByFeeRate.insert(FeeOrder{fee, ops, hash});
    enforceTentativeCapacityLocked();
}

void
TxProposalBuilder::removeTentativeTransaction(Hash const& hash)
{
    ZoneScoped;
    std::lock_guard<std::mutex> guard(mMutex);
    eraseTentativeLocked(hash);
}

void
TxProposalBuilder::removeTransactions(std::vector<Hash> const& hashes)
{
    ZoneScoped;
    std::lock_guard<std::mutex> guard(mMutex);
    for (auto const& hash : hashes)
    {
        eraseLocked(hash);
        eraseTentativeLocked(hash);
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

    expired.clear();
    for (auto const& [acct, chain] : mTentativeByAccount)
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
        eraseTentativeLocked(hash);
    }

    enforceCapacityLocked();
    enforceTentativeCapacityLocked();
}

void
TxProposalBuilder::snapshot(TxFrameList& classicTxs,
                            TxFrameList& sorobanTxs) const
{
    ZoneScoped;
    std::lock_guard<std::mutex> guard(mMutex);
    classicTxs.reserve(mByHash.size() + mTentativeByHash.size());

    auto append = [&](TransactionFrameBasePtr const& tx) {
        if (tx->isSoroban())
        {
            sorobanTxs.push_back(tx);
        }
        else
        {
            classicTxs.push_back(tx);
        }
    };
    auto appendMergedChains = [&](AccountChain const* validated,
                                  AccountChain const* tentative) {
        releaseAssert(validated || tentative);
        if (!validated)
        {
            for (auto const& [seq, entry] : *tentative)
            {
                append(entry.mTx);
            }
            return;
        }
        if (!tentative)
        {
            for (auto const& [seq, entry] : *validated)
            {
                append(entry.mTx);
            }
            return;
        }

        auto v = validated->begin();
        auto const vEnd = validated->end();
        auto t = tentative->begin();
        auto const tEnd = tentative->end();

        while (v != vEnd || t != tEnd)
        {
            if (t == tEnd || (v != vEnd && v->first < t->first))
            {
                append(v->second.mTx);
                ++v;
            }
            else if (v == vEnd || t->first < v->first)
            {
                append(t->second.mTx);
                ++t;
            }
            else
            {
                auto const& validatedTx = v->second.mTx;
                auto const& tentativeTx = t->second.mTx;
                if (feeRate3WayCompare(tentativeTx->getInclusionFee(),
                                       tentativeTx->getNumOperations(),
                                       validatedTx->getInclusionFee(),
                                       validatedTx->getNumOperations()) > 0)
                {
                    append(tentativeTx);
                }
                else
                {
                    append(validatedTx);
                }
                ++v;
                ++t;
            }
        }
    };

    for (auto const& [acct, chain] : mByAccount)
    {
        auto tentative = mTentativeByAccount.find(acct);
        appendMergedChains(&chain, tentative == mTentativeByAccount.end()
                                       ? nullptr
                                       : &tentative->second);
    }
    for (auto const& [acct, chain] : mTentativeByAccount)
    {
        if (mByAccount.find(acct) == mByAccount.end())
        {
            appendMergedChains(nullptr, &chain);
        }
    }
}

size_t
TxProposalBuilder::size() const
{
    std::lock_guard<std::mutex> guard(mMutex);
    return mByHash.size() + mTentativeByHash.size();
}

bool
TxProposalBuilder::eraseTentativeLocked(Hash hash)
{
    auto it = mTentativeByHash.find(hash);
    if (it == mTentativeByHash.end())
    {
        return false;
    }
    auto const [acct, seq] = it->second;

    auto chainIt = mTentativeByAccount.find(acct);
    releaseAssert(chainIt != mTentativeByAccount.end());
    auto entryIt = chainIt->second.find(seq);
    releaseAssert(entryIt != chainIt->second.end());
    auto const tx = entryIt->second.mTx;

    mTentativeByFeeRate.erase(
        FeeOrder{tx->getInclusionFee(), tx->getNumOperations(), hash});
    chainIt->second.erase(entryIt);
    if (chainIt->second.empty())
    {
        mTentativeByAccount.erase(chainIt);
    }
    mTentativeByHash.erase(it);
    return true;
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
TxProposalBuilder::evictTentativeChainTailLocked()
{
    releaseAssert(!mTentativeByFeeRate.empty());
    auto const lowest = *mTentativeByFeeRate.begin();

    auto byHashIt = mTentativeByHash.find(lowest.mHash);
    releaseAssert(byHashIt != mTentativeByHash.end());
    auto const [acct, seq] = byHashIt->second;

    std::vector<Hash> tail;
    auto chainIt = mTentativeByAccount.find(acct);
    releaseAssert(chainIt != mTentativeByAccount.end());
    for (auto it = chainIt->second.lower_bound(seq);
         it != chainIt->second.end(); ++it)
    {
        tail.push_back(it->second.mTx->getFullHash());
    }
    for (auto const& hash : tail)
    {
        eraseTentativeLocked(hash);
    }
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

void
TxProposalBuilder::enforceTentativeCapacityLocked()
{
    // Tentative entries use only capacity not already occupied by validated
    // entries. This keeps the builder's total retention within mMaxTxs while
    // ensuring a pre-verdict local submission can never evict validated work.
    auto const tentativeCapacity =
        mByHash.size() < mMaxTxs ? mMaxTxs - mByHash.size() : 0;
    while (mTentativeByHash.size() > tentativeCapacity)
    {
        evictTentativeChainTailLocked();
    }
}

} // namespace stellar
