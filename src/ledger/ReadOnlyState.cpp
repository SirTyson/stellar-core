// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/ReadOnlyState.h"
#include "bucket/BucketListSnapshot.h"
#include "ledger/LedgerTxn.h"
#include "util/GlobalChecks.h"

namespace stellar
{

LtxReadOnlyResult::LtxReadOnlyResult(LedgerTxnEntry&& entry)
    : mEntry(std::move(entry))
{
}

ReadOnlyResultPtr
LtxReadOnlyResult::create(LedgerTxnEntry&& entry)
{
    return ReadOnlyResultPtr(new LtxReadOnlyResult(std::move(entry)));
}

LedgerEntry const&
LtxReadOnlyResult::entry() const
{
    return mEntry.current();
}

bool
LtxReadOnlyResult::isDead() const
{
    return !static_cast<bool>(mEntry);
}

BucketListReadOnlyResult::BucketListReadOnlyResult(
    std::shared_ptr<LedgerEntry> entry)
    : mEntry(entry)
{
}

ReadOnlyResultPtr
BucketListReadOnlyResult::create(std::shared_ptr<LedgerEntry> entry)
{
    return ReadOnlyResultPtr(new BucketListReadOnlyResult(entry));
}

LedgerEntry const&
BucketListReadOnlyResult::entry() const
{
    releaseAssertOrThrow(mEntry);
    return *mEntry;
}

bool
BucketListReadOnlyResult::isDead() const
{
    return !static_cast<bool>(mEntry);
}

BucketListReadOnlyState::BucketListReadOnlyState(
    SearchableBucketListSnapshot& snapshot)
    : mSnapshot(snapshot)
{
}

ReadOnlyResultPtr
BucketListReadOnlyState::loadEntry(LedgerKey const& key)
{
    auto result = mSnapshot.getLedgerEntry(key);
    return BucketListReadOnlyResult::create(result);
}

LtxReadOnlyState::LtxReadOnlyState(AbstractLedgerTxn& ltx) : mLtx(ltx)
{
    releaseAssert(threadIsMain());
}

ReadOnlyResultPtr
LtxReadOnlyState::loadEntry(LedgerKey const& key)
{
    releaseAssert(threadIsMain());
    auto result = mLtx.load(key);
    return LtxReadOnlyResult::create(std::move(result));
}

AbstractLedgerTxn&
LtxReadOnlyState::getLedgerTxn()
{
    return mLtx;
}
}