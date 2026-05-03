// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/InMemoryIndex.h"
#include "bucket/BucketManager.h"
#include "bucket/BucketUtils.h"
#include "bucket/LedgerCmp.h"
#include "bucket/LiveBucket.h"
#include "util/GlobalChecks.h"
#include "util/ProtocolVersion.h"
#include "util/XDRStream.h"
#include "util/types.h"
#include "xdr/Stellar-ledger-entries.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace stellar
{

namespace
{
size_t
ledgerEntryTypeIndex(LedgerEntryType type)
{
    switch (type)
    {
    case ACCOUNT:
        return 0;
    case TRUSTLINE:
        return 1;
    case OFFER:
        return 2;
    case DATA:
        return 3;
    case CLAIMABLE_BALANCE:
        return 4;
    case LIQUIDITY_POOL:
        return 5;
    case CONTRACT_DATA:
        return 6;
    case CONTRACT_CODE:
        return 7;
    case CONFIG_SETTING:
        return 8;
    case TTL:
        return 9;
    }

    releaseAssertOrThrow(false);
    return 0;
}

// Direct, single-pass identity equality: compare the identifying key fields
// of `data` (the .data of an INIT/LIVE LedgerEntry) against the LedgerKey
// `key`. Equivalent in semantics to LedgerEntryIdCmp but avoids the double
// comparison pattern (`!cmp(a,b) && !cmp(b,a)`) and any intermediate
// LedgerKey construction.
bool
ledgerEntryDataKeyEqual(LedgerEntry::_data_t const& data, LedgerKey const& key)
{
    if (data.type() != key.type())
    {
        return false;
    }
    switch (key.type())
    {
    case ACCOUNT:
        return data.account().accountID == key.account().accountID;
    case TRUSTLINE:
    {
        auto const& dl = data.trustLine();
        auto const& kl = key.trustLine();
        return dl.accountID == kl.accountID && dl.asset == kl.asset;
    }
    case OFFER:
    {
        auto const& d = data.offer();
        auto const& k = key.offer();
        return d.offerID == k.offerID && d.sellerID == k.sellerID;
    }
    case DATA:
    {
        auto const& d = data.data();
        auto const& k = key.data();
        return d.accountID == k.accountID && d.dataName == k.dataName;
    }
    case CLAIMABLE_BALANCE:
        return data.claimableBalance().balanceID ==
               key.claimableBalance().balanceID;
    case LIQUIDITY_POOL:
        return data.liquidityPool().liquidityPoolID ==
               key.liquidityPool().liquidityPoolID;
    case CONTRACT_DATA:
    {
        auto const& d = data.contractData();
        auto const& k = key.contractData();
        return d.durability == k.durability && d.contract == k.contract &&
               d.key == k.key;
    }
    case CONTRACT_CODE:
        return data.contractCode().hash == key.contractCode().hash;
    case CONFIG_SETTING:
        return data.configSetting().configSettingID() ==
               key.configSetting().configSettingID;
    case TTL:
        return data.ttl().keyHash == key.ttl().keyHash;
    }
    return false;
}

bool
bucketEntryKeyEqual(BucketEntry const& be, LedgerKey const& key)
{
    switch (be.type())
    {
    case LIVEENTRY:
    case INITENTRY:
        return ledgerEntryDataKeyEqual(be.liveEntry().data, key);
    case DEADENTRY:
        return be.deadEntry() == key;
    case METAENTRY:
    default:
        throw std::invalid_argument("Tried to get key for METAENTRY");
    }
}

// Direct entry-vs-entry identity equality used during flat-index duplicate
// detection. Falls back to extracting one bucket key and comparing against the
// other entry's identifying fields via the fast path above.
bool
bucketEntriesKeyEqual(BucketEntry const& lhs, BucketEntry const& rhs)
{
    if (rhs.type() == DEADENTRY)
    {
        return bucketEntryKeyEqual(lhs, rhs.deadEntry());
    }
    if (lhs.type() == DEADENTRY)
    {
        return bucketEntryKeyEqual(rhs, lhs.deadEntry());
    }
    auto const& ld = lhs.liveEntry().data;
    auto const& rd = rhs.liveEntry().data;
    if (ld.type() != rd.type())
    {
        return false;
    }
    switch (ld.type())
    {
    case ACCOUNT:
        return ld.account().accountID == rd.account().accountID;
    case TRUSTLINE:
    {
        auto const& l = ld.trustLine();
        auto const& r = rd.trustLine();
        return l.accountID == r.accountID && l.asset == r.asset;
    }
    case OFFER:
    {
        auto const& l = ld.offer();
        auto const& r = rd.offer();
        return l.offerID == r.offerID && l.sellerID == r.sellerID;
    }
    case DATA:
    {
        auto const& l = ld.data();
        auto const& r = rd.data();
        return l.accountID == r.accountID && l.dataName == r.dataName;
    }
    case CLAIMABLE_BALANCE:
        return ld.claimableBalance().balanceID ==
               rd.claimableBalance().balanceID;
    case LIQUIDITY_POOL:
        return ld.liquidityPool().liquidityPoolID ==
               rd.liquidityPool().liquidityPoolID;
    case CONTRACT_DATA:
    {
        auto const& l = ld.contractData();
        auto const& r = rd.contractData();
        return l.durability == r.durability && l.contract == r.contract &&
               l.key == r.key;
    }
    case CONTRACT_CODE:
        return ld.contractCode().hash == rd.contractCode().hash;
    case CONFIG_SETTING:
        return ld.configSetting().configSettingID() ==
               rd.configSetting().configSettingID();
    case TTL:
        return ld.ttl().keyHash == rd.ttl().keyHash;
    }
    return false;
}

bool
inMemoryEntryLess(InternalInMemoryBucketEntry const& lhs,
                  InternalInMemoryBucketEntry const& rhs)
{
    if (lhs.type() != rhs.type())
    {
        return lhs.type() < rhs.type();
    }
    if (lhs.hash() != rhs.hash())
    {
        return lhs.hash() < rhs.hash();
    }

    return BucketEntryIdCmp<LiveBucket>{}(*lhs.get(), *rhs.get());
}

// Helper function to process a single bucket entry for InMemoryIndex
// construction
void
processEntry(BucketEntry const& be, InMemoryBucketState& inMemoryState,
             AssetPoolIDMap& assetPoolIDMap, BucketEntryCounters& counters,
             std::streamoff& lastOffset,
             std::map<LedgerEntryType, std::streamoff>& typeStartOffsets,
             std::map<LedgerEntryType, std::streamoff>& typeEndOffsets,
             std::optional<LedgerEntryType>& lastTypeSeen)
{
    counters.template count<LiveBucket>(be);

    // Populate assetPoolIDMap
    LedgerKey lk = getBucketLedgerKey(be);
    if (be.type() == INITENTRY)
    {
        if (lk.type() == LIQUIDITY_POOL)
        {
            auto const& poolParams = be.liveEntry()
                                         .data.liquidityPool()
                                         .body.constantProduct()
                                         .params;
            assetPoolIDMap[poolParams.assetA].emplace_back(
                lk.liquidityPool().liquidityPoolID);
            assetPoolIDMap[poolParams.assetB].emplace_back(
                lk.liquidityPool().liquidityPoolID);
        }
    }

    inMemoryState.insert(be);
    updateTypeBoundaries(lk.type(), lastOffset, typeStartOffsets,
                         typeEndOffsets, lastTypeSeen);
}
}

InternalInMemoryBucketEntry::InternalInMemoryBucketEntry(IndexPtrT entry)
    : mEntry(std::move(entry))
    , mHash(0)
    , mType(ACCOUNT)
{
    releaseAssertOrThrow(mEntry);
    auto key = getBucketLedgerKey(*mEntry);
    mHash = std::hash<LedgerKey>{}(key);
    mType = key.type();
}

bool
InternalInMemoryBucketEntry::keyEquals(LedgerKey const& key) const
{
    return bucketEntryKeyEqual(*mEntry, key);
}

bool
InternalInMemoryBucketEntry::operator==(
    InternalInMemoryBucketEntry const& other) const
{
    return bucketEntriesKeyEqual(*mEntry, *other.mEntry);
}

void
InMemoryBucketState::insert(BucketEntry const& be)
{
    mEntries.emplace_back(std::make_shared<BucketEntry const>(be));
}

void
InMemoryBucketState::finalize()
{
    std::sort(mEntries.begin(), mEntries.end(), inMemoryEntryLess);
    mEntryRanges.fill({0, 0});

    for (size_t i = 1; i < mEntries.size(); ++i)
    {
        releaseAssertOrThrow(!(mEntries[i - 1].hash() == mEntries[i].hash() &&
                               mEntries[i - 1] == mEntries[i]));
    }

    size_t rangeStart = 0;
    while (rangeStart < mEntries.size())
    {
        auto const type = mEntries[rangeStart].type();
        auto rangeEnd = rangeStart + 1;
        while (rangeEnd < mEntries.size() && mEntries[rangeEnd].type() == type)
        {
            ++rangeEnd;
        }

        mEntryRanges[ledgerEntryTypeIndex(type)] = {rangeStart, rangeEnd};
        rangeStart = rangeEnd;
    }
}

void
InMemoryBucketState::reserve(size_t size)
{
    mEntries.reserve(size);
}

// Perform a hash lookup over the type-specific flat index; start is ignored for
// in-memory indexes.
std::pair<IndexReturnT, InMemoryBucketState::IterT>
InMemoryBucketState::scan(IterT start, LedgerKey const& searchKey) const
{
    ZoneScoped;
    auto const searchHash = std::hash<LedgerKey>{}(searchKey);
    auto const [rangeStart, rangeEnd] =
        mEntryRanges[ledgerEntryTypeIndex(searchKey.type())];
    auto const begin = mEntries.begin() + rangeStart;
    auto const end = mEntries.begin() + rangeEnd;
    auto it = std::lower_bound(
        begin, end, searchHash,
        [](InternalInMemoryBucketEntry const& entry, size_t hash) {
            return entry.hash() < hash;
        });

    while (it != end && it->hash() == searchHash)
    {
        if (it->keyEquals(searchKey))
        {
            return {IndexReturnT(it->get()), mEntries.begin()};
        }
        ++it;
    }

    return {IndexReturnT(), mEntries.begin()};
}

InMemoryIndex::InMemoryIndex(BucketManager& bm,
                             std::vector<BucketEntry> const& inMemoryState,
                             BucketMetadata const& metadata)
{
    ZoneScoped;

    // 4 bytes of size info between BucketEntries on disk
    constexpr std::streamoff xdrOverheadBetweenEntries = 4;

    // Calculate the starting offset for the first entry. Note for older
    // protocols, there is no METAENTRY and the first entry starts at offset 0.
    std::streamoff lastOffset = 0;
    if (protocolVersionStartsFrom(
            metadata.ledgerVersion,
            LiveBucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY))
    {
        // METAENTRY on disk is: 4 bytes size prefix + 4 bytes BucketEntry
        // discriminant + metadata content
        constexpr std::streamoff xdrOverheadForMetaEntry = 4;
        lastOffset = xdr::xdr_size(metadata) + xdrOverheadForMetaEntry +
                     xdrOverheadBetweenEntries;
    }

    std::map<LedgerEntryType, std::streamoff> typeStartOffsets;
    std::map<LedgerEntryType, std::streamoff> typeEndOffsets;
    std::optional<LedgerEntryType> lastTypeSeen = std::nullopt;
    mInMemoryState.reserve(inMemoryState.size());

    for (auto const& be : inMemoryState)
    {
        releaseAssertOrThrow(be.type() != METAENTRY);

        processEntry(be, mInMemoryState, mAssetPoolIDMap, mCounters, lastOffset,
                     typeStartOffsets, typeEndOffsets, lastTypeSeen);

        lastOffset += xdr::xdr_size(be) + xdrOverheadBetweenEntries;
    }

    mInMemoryState.finalize();

    // Build the final type ranges map
    mTypeRanges = buildTypeRangesMap(typeStartOffsets, typeEndOffsets);
}

InMemoryIndex::InMemoryIndex(BucketManager const& bm,
                             std::filesystem::path const& filename,
                             SHA256* hasher)
{
    ZoneScoped;
    XDRInputFileStream in;
    in.open(filename.string());
    BucketEntry be;
    size_t iter = 0;
    std::streamoff lastOffset = 0;
    std::map<LedgerEntryType, std::streamoff> typeStartOffsets;
    std::map<LedgerEntryType, std::streamoff> typeEndOffsets;
    std::optional<LedgerEntryType> lastTypeSeen = std::nullopt;

    while (in && in.readOne(be, hasher))
    {
        if (++iter >= 1000)
        {
            iter = 0;
            if (bm.isShutdown())
            {
                throw std::runtime_error("Incomplete bucket index due to "
                                         "BucketManager shutdown");
            }
        }

        if (be.type() == METAENTRY)
        {
            lastOffset = in.pos();
            continue;
        }

        processEntry(be, mInMemoryState, mAssetPoolIDMap, mCounters, lastOffset,
                     typeStartOffsets, typeEndOffsets, lastTypeSeen);
        lastOffset = in.pos();
    }

    mInMemoryState.finalize();

    // Build the final type ranges map
    mTypeRanges = buildTypeRangesMap(typeStartOffsets, typeEndOffsets);
}

std::optional<std::pair<std::streamoff, std::streamoff>>
InMemoryIndex::getRangeForType(LedgerEntryType type) const
{
    auto it = mTypeRanges.find(type);
    if (it != mTypeRanges.end())
    {
        return std::make_optional(it->second);
    }

    return std::nullopt;
}

#ifdef BUILD_TESTS
bool
InMemoryIndex::operator==(InMemoryIndex const& in) const
{
    return mInMemoryState == in.mInMemoryState &&
           mAssetPoolIDMap == in.mAssetPoolIDMap &&
           mTypeRanges == in.mTypeRanges && mCounters == in.mCounters;
}
#endif
}
