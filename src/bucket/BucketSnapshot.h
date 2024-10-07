#pragma once

// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/Bucket.h"
#include "bucket/LedgerCmp.h"
#include "util/NonCopyable.h"
#include <list>
#include <set>

#include <optional>

namespace stellar
{

class XDRInputFileStream;
struct EvictionResultEntry;
class LedgerKeyMeter;
class SearchableLiveBucketListSnapshot;

// A lightweight wrapper around Bucket for thread safe BucketListDB lookups
template <class BucketT> class BucketSnapshotBase : public NonMovable
{
    static_assert(std::is_same_v<BucketT, LiveBucket> ||
                  std::is_same_v<BucketT, HotArchiveBucket>);

  protected:
    using BucketEntryT = std::conditional_t<std::is_same_v<BucketT, LiveBucket>,
                                            BucketEntry, HotArchiveBucketEntry>;

    std::shared_ptr<BucketT const> const mBucket;

    // Lazily-constructed and retained for read path.
    mutable std::unique_ptr<XDRInputFileStream> mStream{};

    // Returns (lazily-constructed) file stream for bucket file. Note
    // this might be in some random position left over from a previous read --
    // must be seek()'ed before use.
    XDRInputFileStream& getStream() const;

    // Loads the bucket entry for LedgerKey k. Starts at file offset pos and
    // reads until key is found or the end of the page. Returns <BucketEntry,
    // bloomMiss>, where bloomMiss is true if a bloomMiss occurred during the
    // load.
    std::pair<std::optional<BucketEntryT>, bool>
    getEntryAtOffset(LedgerKey const& k, std::streamoff pos,
                     size_t pageSize) const;

    BucketSnapshotBase(std::shared_ptr<BucketT const> const b);

    // Only allow copy constructor, is threadsafe
    BucketSnapshotBase(BucketSnapshotBase const& b);
    BucketSnapshotBase& operator=(BucketSnapshotBase const&) = delete;

  public:
    bool isEmpty() const;
    std::shared_ptr<BucketT const> getRawBucket() const;

    // Loads bucket entry for LedgerKey k. Returns <BucketEntry, bloomMiss>,
    // where bloomMiss is true if a bloomMiss occurred during the load.
    std::pair<std::optional<BucketEntryT>, bool>
    getBucketEntry(LedgerKey const& k) const;

    // TODO: Restrict limits to LiveBucket only
    // Loads LedgerEntry's for given keys. When a key is found, the
    // entry is added to result and the key is removed from keys.
    // If a pointer to a LedgerKeyMeter is provided, a key will only be loaded
    // if the meter has a transaction with sufficient read quota for the key.
    void loadKeysWithLimits(std::set<LedgerKey, LedgerEntryIdCmp>& keys,
                            std::vector<LedgerEntry>& result,
                            LedgerKeyMeter* lkMeter) const;

    // friend struct BucketLevelSnapshot<BucketT>;
};

class LiveBucketSnapshot : public BucketSnapshotBase<LiveBucket>
{
  public:
    LiveBucketSnapshot(std::shared_ptr<LiveBucket const> const b);

    // Only allow copy constructors, is threadsafe
    LiveBucketSnapshot(LiveBucketSnapshot const& b);

    // Return all PoolIDs that contain the given asset on either side of the
    // pool
    std::vector<PoolID> const& getPoolIDsByAsset(Asset const& asset) const;

    bool scanForEviction(EvictionIterator& iter, uint32_t& bytesToScan,
                         uint32_t ledgerSeq,
                         std::list<EvictionResultEntry>& evictableKeys,
                         SearchableLiveBucketListSnapshot& bl) const;
};

class HotArchiveBucketSnapshot : public BucketSnapshotBase<HotArchiveBucket>
{
  public:
    HotArchiveBucketSnapshot(std::shared_ptr<HotArchiveBucket const> const b);

    // Only allow copy constructors, is threadsafe
    HotArchiveBucketSnapshot(HotArchiveBucketSnapshot const& b);
};
}