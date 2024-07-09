#pragma once

// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerTxnEntry.h"
#include "util/NonCopyable.h"
#include "util/types.h"

#include <memory>

namespace stellar
{

class AbstractLedgerTxn;
class SearchableBucketListSnapshot;
class ReadOnlyResult;
class ReadOnlyState;

typedef std::shared_ptr<ReadOnlyResult> ReadOnlyResultPtr;

// ReadOnlyResult is a generic wrapper for the result of loading a LedgerEntry
// loaded either from a LedgerTxn or from a BucketList snapshot.
class ReadOnlyResult
{
  public:
    virtual LedgerEntry const& entry() const = 0;
    virtual bool isDead() const = 0;
};

class LtxReadOnlyResult : public ReadOnlyResult
{
  private:
    LedgerTxnEntry mEntry;
    LtxReadOnlyResult(LedgerTxnEntry&& entry);

  public:
    static ReadOnlyResultPtr create(LedgerTxnEntry&& entry);

    LedgerEntry const& entry() const override;
    bool isDead() const override;
};

class BucketListReadOnlyResult : public ReadOnlyResult
{
  private:
    std::shared_ptr<LedgerEntry> mEntry;
    BucketListReadOnlyResult(std::shared_ptr<LedgerEntry> entry);

  public:
    static ReadOnlyResultPtr create(std::shared_ptr<LedgerEntry> entry);

    LedgerEntry const& entry() const override;
    bool isDead() const override;
};

// ReadOnlyState is an interface for loading LedgerEntries from either a
// LedgerTxn object or a SearchableBucketListSnapshot
class ReadOnlyState
{
  public:
    virtual ReadOnlyResultPtr loadEntry(LedgerKey const& key) = 0;
};

class BucketListReadOnlyState : public ReadOnlyState
{
  private:
    SearchableBucketListSnapshot& mSnapshot;

  public:
    BucketListReadOnlyState(SearchableBucketListSnapshot& snapshot);

    ReadOnlyResultPtr loadEntry(LedgerKey const& key) override;
};

class LtxReadOnlyState : public ReadOnlyState
{
  private:
    AbstractLedgerTxn& mLtx;

  public:
    LtxReadOnlyState(AbstractLedgerTxn& ledgerTxn);

    ReadOnlyResultPtr loadEntry(LedgerKey const& key) override;
    AbstractLedgerTxn& getLedgerTxn();
};
}