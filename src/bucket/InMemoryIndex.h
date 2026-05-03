// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "bucket/BucketIndexUtils.h"
#include "bucket/BucketUtils.h"
#include "xdr/Stellar-ledger-entries.h"

#include "ledger/LedgerHashUtils.h"
#include <array>
#include <vector>

namespace stellar
{

class SHA256;

// LedgerKey sizes usually dominate LedgerEntry size, so we don't want to store
// a key-value map. Instead, we store the cached BucketEntry with its key hash
// and type in a flat lookup index.
class InternalInMemoryBucketEntry
{
  private:
    IndexPtrT mEntry;
    size_t mHash;
    LedgerEntryType mType;

  public:
    explicit InternalInMemoryBucketEntry(IndexPtrT entry);

    size_t
    hash() const
    {
        return mHash;
    }

    bool keyEquals(LedgerKey const& key) const;
    bool operator==(InternalInMemoryBucketEntry const& other) const;

    LedgerEntryType
    type() const
    {
        return mType;
    }

    IndexPtrT const&
    get() const
    {
        return mEntry;
    }
};

// For small Buckets, we can cache all contents in memory. Because we cache all
// entries, the index is just as large as the Bucket itself, so we never persist
// this index type. It is always recreated on startup.
class InMemoryBucketState : public NonMovableOrCopyable
{
    static constexpr size_t kLedgerEntryTypeCount = 10;

    using InMemoryEntries = std::vector<InternalInMemoryBucketEntry>;
    using EntryRange = std::pair<size_t, size_t>;

    InMemoryEntries mEntries;
    std::array<EntryRange, kLedgerEntryTypeCount> mEntryRanges{};

  public:
    using IterT = InMemoryEntries::const_iterator;

    // Insert a LedgerEntry (INIT/LIVE) into the cache.
    void insert(BucketEntry const& be);

    // Sort entries into a cache-local immutable lookup index and assert no
    // duplicate keys were inserted.
    void finalize();

    void reserve(size_t size);

    // Find a LedgerEntry. IterT::begin is always returned, and start is
    // ignored. This interface just helps maintain consistency with
    // DiskIndex::scan.
    std::pair<IndexReturnT, IterT> scan(IterT start,
                                        LedgerKey const& searchKey) const;

    IterT
    begin() const
    {
        return mEntries.begin();
    }
    IterT
    end() const
    {
        return mEntries.end();
    }

#ifdef BUILD_TESTS
    bool
    operator==(InMemoryBucketState const& in) const
    {
        return mEntries == in.mEntries;
    }
#endif
};

class InMemoryIndex
{
  private:
    InMemoryBucketState mInMemoryState;
    AssetPoolIDMap mAssetPoolIDMap;
    BucketEntryCounters mCounters{};
    std::map<LedgerEntryType, std::pair<std::streamoff, std::streamoff>>
        mTypeRanges;

  public:
    using IterT = InMemoryBucketState::IterT;

    InMemoryIndex(BucketManager const& bm,
                  std::filesystem::path const& filename, SHA256* hasher);

    InMemoryIndex(BucketManager& bm,
                  std::vector<BucketEntry> const& inMemoryState,
                  BucketMetadata const& metadata);

    IterT
    begin() const
    {
        return mInMemoryState.begin();
    }
    IterT
    end() const
    {
        return mInMemoryState.end();
    }

    AssetPoolIDMap const&
    getAssetPoolIDMap() const
    {
        return mAssetPoolIDMap;
    }

    BucketEntryCounters const&
    getBucketEntryCounters() const
    {
        return mCounters;
    }

    std::pair<IndexReturnT, IterT>
    scan(IterT start, LedgerKey const& searchKey) const
    {
        return mInMemoryState.scan(start, searchKey);
    }

    std::optional<std::pair<std::streamoff, std::streamoff>>
    getRangeForType(LedgerEntryType type) const;

#ifdef BUILD_TESTS
    bool operator==(InMemoryIndex const& in) const;
#endif
};
}
