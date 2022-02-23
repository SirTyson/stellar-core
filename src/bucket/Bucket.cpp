// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// ASIO is somewhat particular about when it gets included -- it wants to be the
// first to include <windows.h> -- so we try to include it before everything
// else.
#include "util/asio.h"
#include "bucket/Bucket.h"
#include "bucket/BucketApplicator.h"
#include "bucket/BucketInputIterator.h"
#include "bucket/BucketList.h"
#include "bucket/BucketManager.h"
#include "bucket/BucketOutputIterator.h"
#include "bucket/LedgerCmp.h"
#include "bucket/MergeKey.h"
#include "crypto/Hex.h"
#include "crypto/Random.h"
#include "crypto/SHA.h"
#include "database/Database.h"
#include "main/Application.h"
#include "medida/timer.h"
#include "util/Fs.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/TmpDir.h"
#include "util/XDRStream.h"
#include "util/types.h"
#include "xdr/Stellar-ledger.h"
#include "xdrpp/message.h"
#include <Tracy.hpp>
#include <cstdint>
#include <fmt/format.h>
#include <future>
#include <unistd.h>

namespace stellar
{

template <size_t N>
static uint64_t
wordFromBytes(std::array<std::uint8_t, N> const& arr)
{
    uint64_t res{0};
    res |= static_cast<uint64_t>(arr[0]) << 56;
    res |= static_cast<uint64_t>(arr[1]) << 48;
    res |= static_cast<uint64_t>(arr[2]) << 40;
    res |= static_cast<uint64_t>(arr[3]) << 32;
    res |= static_cast<uint64_t>(arr[4]) << 24;
    res |= static_cast<uint64_t>(arr[5]) << 16;
    res |= static_cast<uint64_t>(arr[6]) << 8;
    res |= static_cast<uint64_t>(arr[7]);
    return res;
}

static inline uint8_t
sixbitOfAlnum(uint8_t uch)
{
    if (uch == 0)
    {
        return 0;
    }
    char ch = static_cast<char>(uch);
    releaseAssert(std::isalnum(ch));
    if ('0' <= ch && ch <= '9')
    {
        return static_cast<uint8_t>(ch - '0');
    }
    else if ('A' <= ch && ch <= 'Z')
    {
        return 10 + static_cast<uint8_t>(ch - 'A');
    }
    else
    {
        releaseAssert('a' <= ch && ch <= 'z');
        return 36 + static_cast<uint8_t>(ch - 'a');
    }
}

template <typename LK>
std::optional<ShortLedgerKey>
Bucket::getShortLedgerKey(LK const& k, uint32_t protocolVersion)
{
    // A ShortLedgerKey has to have the following features:
    //
    //   - Preserves non-strict order and strict equality from LedgerKey: a <= b
    //     => SLK(a) <= SLK(b) and a == b => SLK(a) == SLK(b). Doesn't
    //     necessarily preserve strict inequality, a < b might not imply SLK(a)
    //     < SLK(b).
    //
    //   - Uses as many bits as it safely can from the most-unique part of each
    //     existing LedgerEntry (typically its public key).
    //
    // The general structure of the mapping is just "take high order bits of
    // fields in their lexicographical order".

    ShortLedgerKey res;

    // Top 3 bits are type (there are only 5 types so this fits).
    res |= static_cast<uint64_t>(k.type()) << 61;

    // Low 61 bits are from the rest
    switch (k.type())
    {
    case ACCOUNT:
        // for account the layout is just 61 bits of pubkey.
        res |= wordFromBytes(k.account().accountID.ed25519()) >> 3;
        break;

    case TRUSTLINE:
    {
        // for trustline the layout is
        //
        // 39 bits account pubkey
        // 2 bits of asset type
        // 12 bits of asset alphanum + 8 bits issuer
        // OR
        // 20 bits poolID
        auto const& tl = k.trustLine();
        auto const& a = tl.asset;
        if (!isAssetValid<TrustLineAsset>(a, protocolVersion))
        {
            return std::nullopt;
        }

        res |= (wordFromBytes(tl.accountID.ed25519()) >> 3) & ~0x3fffff;
        res |= (a.type() << 20);
        switch (a.type())
        {
        case ASSET_TYPE_NATIVE:
            break;
        case ASSET_TYPE_CREDIT_ALPHANUM4:
            res |= sixbitOfAlnum(a.alphaNum4().assetCode[0]) << 14;
            res |= sixbitOfAlnum(a.alphaNum4().assetCode[1]) << 8;
            res |= a.alphaNum4().issuer.ed25519()[0];
            break;
        case ASSET_TYPE_CREDIT_ALPHANUM12:
            res |= sixbitOfAlnum(a.alphaNum12().assetCode[0]) << 14;
            res |= sixbitOfAlnum(a.alphaNum12().assetCode[1]) << 8;
            res |= a.alphaNum12().issuer.ed25519()[0];
            break;
        case ASSET_TYPE_POOL_SHARE:
            res |= wordFromBytes(a.liquidityPoolID()) >> 44;
            break;
        }
    }
    break;
    case OFFER:
        // 45 bits of accountID and 16 bits of offerID
        res |= (wordFromBytes(k.offer().sellerID.ed25519()) >> 3) & ~0xffff;
        res |= (k.offer().offerID >> 45);
        break;
    case DATA:
        // for data the layout is 45 bits of accountID and
        // 16 bits of dataName
        res |= (wordFromBytes(k.data().accountID.ed25519()) >> 3) & ~0xffff;
        if (k.data().dataName.size() > 0)
        {
            res |= (k.data().dataName[0] << 8);
        }
        if (k.data().dataName.size() > 1)
        {
            res |= k.data().dataName[1];
        }
        break;
    case CLAIMABLE_BALANCE:
        res |= wordFromBytes(k.claimableBalance().balanceID.v0()) >> 3;
        break;
    case LIQUIDITY_POOL:
        res |= wordFromBytes(k.liquidityPool().liquidityPoolID) >> 3;
        break;
    }
    return std::make_optional(res);
}

static std::optional<ShortLedgerKey>
getBucketEntryShortLedgerKey(BucketEntry const& be, uint32_t ledgerVersion)
{
    switch (be.type())
    {
    case LIVEENTRY:
    case INITENTRY:
        return Bucket::getShortLedgerKey<LedgerEntry::_data_t>(
            be.liveEntry().data, ledgerVersion);
    case DEADENTRY:
        return Bucket::getShortLedgerKey<LedgerKey>(be.deadEntry(),
                                                    ledgerVersion);
    case METAENTRY:
    default:
        break;
    }
    return std::nullopt;
}

bool
ShortLedgerKey::operator<(ShortLedgerKey const& b) const
{
    LedgerEntryType aty = static_cast<LedgerEntryType>(this->key >> 61);
    LedgerEntryType bty = static_cast<LedgerEntryType>(b.key >> 61);

    // If at least one account is not associated with an account or
    // account subentry
    if (aty >= CLAIMABLE_BALANCE || bty >= CLAIMABLE_BALANCE)
    {
        // Order by type if types differ
        if (aty < bty)
            return true;

        if (aty > bty)
            return false;

        // Else if types are the same order strictly
        return this->key < b.key;
    }

    uint64_t aID = this->key & ACCOUNT_ID_MASK;
    uint64_t bID = b.key & ACCOUNT_ID_MASK;

    // If associated accountIDs are different, order by accountID
    if (aID != bID)
        return aID < bID;

    // If accountIDs are the same, sort by type
    if (aty < bty)
        return true;

    if (aty > bty)
        return false;

    // If accountID's are the same and entrie's are same type, order by
    // entire key
    return this->key < b.key;
}

BucketIndex::BucketIndex(std::shared_ptr<Bucket const> b)
{
    if (b->getV2Filename().empty())
    {
        return;
    }

    mLedgerVersion = Bucket::getBucketVersion(b);
    XDRInputFileStream in;
    in.open(b->getV2Filename());
    size_t pos = 0;
    BucketEntry be;
    // std::vector<BucketEntry> bes;
    while (in && in.readOne(be))
    {
        auto bek = getBucketEntryShortLedgerKey(be, mLedgerVersion);
        if (bek.has_value())
        {
            CLOG_TRACE(Bucket, "Indexed {} at {} in {}", bek.value().key, pos,
                       std::filesystem::path(b->getV2Filename()).filename());
            // Assert ShortLedgerKeys and Buckets are sorted correctly
            // for (size_t i = 0; i < bes.size(); ++i)
            // {
            //     releaseAssert(BucketEntryIdCmpV2{}(bes[i], be));
            //     releaseAssert(mKeys[i] < bek.value());
            // }

            // bes.push_back(be);
            mKeys.emplace_back(bek.value());
            mPositions.emplace_back(pos);
        }
        pos = in.pos();
    }

    CLOG_INFO(Bucket, "Indexed {} positions in {}", mKeys.size(),
              std::filesystem::path(b->getV2Filename()).filename());
}

std::optional<off_t>
BucketIndex::lookup(LedgerKey const& k) const
{
    std::optional<ShortLedgerKey> slk =
        Bucket::getShortLedgerKey(k, mLedgerVersion);
    if (!slk)
    {
        return std::nullopt;
    }

    auto i =
        std::lower_bound(mKeys.begin(), mKeys.end(), *slk,
                         [](auto const& a, auto const& b) { return a < b; });
    if (i == mKeys.end() || *i != *slk)
    {
        return std::nullopt;
    }
    auto n = i - mKeys.begin();
    return std::make_optional(mPositions.at(n));
}

Bucket::Bucket(std::string const& filename, Hash const& hash,
               std::string const& sortedV2Filename)
    : mFilename(filename), mV2Filename(sortedV2Filename), mHash(hash)
{
    releaseAssert(filename.empty() || fs::exists(filename));
    releaseAssert(sortedV2Filename.empty() || fs::exists(sortedV2Filename));
    if (!filename.empty())
    {
        CLOG_INFO(Bucket, "Bucket::Bucket() created, file exists : {}",
                  filename);
        mSize = fs::size(filename);
    }
}

Bucket::Bucket()
{
}

BucketIndex const&
Bucket::getIndex()
{
    if (!mIndex)
    {
        if (mV2Filename.empty())
        {
            CLOG_INFO(Bucket,
                      "WARN Bucket::getIndex() bucket with empty filename.");
            // Assert that this bucket is not backed by any file to make sure
            // that V2 is not missing if V1 sorted file is present
            releaseAssert(mFilename.empty());
        }
        else
        {
            CLOG_INFO(Bucket, "Bucket::getIndex() indexing bucket {}",
                      mV2Filename);
        }

        mIndex = std::make_unique<BucketIndex>(shared_from_this());
    }
    return *mIndex;
}

XDRInputFileStream&
Bucket::getStream()
{
    if (!mStream)
    {
        mStream = std::make_unique<XDRInputFileStream>();
        if (!mV2Filename.empty())
        {
            mStream->open(mV2Filename);
        }
    }
    return *mStream;
}

std::optional<BucketEntry>
Bucket::getBucketEntry(LedgerKey const& k)
{
    auto skop = getShortLedgerKey<LedgerKey const>(
        k, getBucketVersion(shared_from_this()));
    auto pos = getIndex().lookup(k);
    if (pos.has_value())
    {
        releaseAssert(skop.has_value());
        auto sk = *skop;
        BucketEntry be;
        auto& stream = getStream();
        CLOG_TRACE(Bucket, "Seeking bucket {} to position {} for {:x}",
                   std::filesystem::path(mV2Filename).filename(), pos.value(),
                   sk.key);
        stream.seek(pos.value());
        while (stream && stream.readOne(be) &&
               getBucketEntryShortLedgerKey(
                   be, getBucketVersion(shared_from_this())) == sk)
        {
            LedgerKey currKey;
            switch (be.type())
            {
            case INITENTRY:
            case LIVEENTRY:
                currKey = LedgerEntryKey(be.liveEntry());
                break;
            case DEADENTRY:
                currKey = be.deadEntry();
                break;
            default:
                throw std::runtime_error("Indexed meta entry");
            }

            if (currKey == k)
            {
                CLOG_TRACE(Bucket, "Found BE for {:x} in bucket {}", sk.key,
                           std::filesystem::path(mV2Filename).filename());
                return std::make_optional(be);
            }
        }
    }
    return std::nullopt;
}

Hash const&
Bucket::getHash() const
{
    return mHash;
}

std::string const&
Bucket::getFilename() const
{
    return mFilename;
}

std::string const&
Bucket::getV2Filename() const
{
    return mV2Filename;
}

std::string&
Bucket::getV2Filename()
{
    return mV2Filename;
}

size_t
Bucket::getSize() const
{
    return mSize;
}

bool
Bucket::containsBucketIdentity(BucketEntry const& id) const
{
    BucketEntryIdCmp cmp;
    BucketInputIterator iter(shared_from_this());
    while (iter)
    {
        if (!(cmp(*iter, id) || cmp(id, *iter)))
        {
            return true;
        }
        ++iter;
    }
    return false;
}

#ifdef BUILD_TESTS
void
Bucket::apply(Application& app) const
{
    ZoneScoped;

    BucketApplicator applicator(app, app.getConfig().LEDGER_PROTOCOL_VERSION,
                                shared_from_this(),
                                [](LedgerEntryType) { return true; });
    BucketApplicator::Counters counters(app.getClock().now());
    while (applicator)
    {
        applicator.advance(counters);
    }
    counters.logInfo("direct", 0, app.getClock().now());
}
#endif // BUILD_TESTS

std::vector<BucketEntry>
Bucket::convertToBucketEntry(bool useInit,
                             std::vector<LedgerEntry> const& initEntries,
                             std::vector<LedgerEntry> const& liveEntries,
                             std::vector<LedgerKey> const& deadEntries)
{
    std::vector<BucketEntry> bucket;
    for (auto const& e : initEntries)
    {
        BucketEntry ce;
        ce.type(useInit ? INITENTRY : LIVEENTRY);
        ce.liveEntry() = e;
        bucket.push_back(ce);
    }
    for (auto const& e : liveEntries)
    {
        BucketEntry ce;
        ce.type(LIVEENTRY);
        ce.liveEntry() = e;
        bucket.push_back(ce);
    }
    for (auto const& e : deadEntries)
    {
        BucketEntry ce;
        ce.type(DEADENTRY);
        ce.deadEntry() = e;
        bucket.push_back(ce);
    }

    BucketEntryIdCmp cmp;
    std::sort(bucket.begin(), bucket.end(), cmp);
    releaseAssert(std::adjacent_find(
                      bucket.begin(), bucket.end(),
                      [&cmp](BucketEntry const& lhs, BucketEntry const& rhs) {
                          return !cmp(lhs, rhs);
                      }) == bucket.end());
    return bucket;
}

std::shared_ptr<Bucket>
Bucket::fresh(BucketManager& bucketManager, uint32_t protocolVersion,
              std::vector<LedgerEntry> const& initEntries,
              std::vector<LedgerEntry> const& liveEntries,
              std::vector<LedgerKey> const& deadEntries, bool countMergeEvents,
              asio::io_context& ctx, bool doFsync)
{
    ZoneScoped;
    // When building fresh buckets after protocol version 10 (i.e. version
    // 11-or-after) we differentiate INITENTRY from LIVEENTRY. In older
    // protocols, for compatibility sake, we mark both cases as LIVEENTRY.
    bool useInit =
        (protocolVersion >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY);

    BucketMetadata meta;
    meta.ledgerVersion = protocolVersion;
    auto entries =
        convertToBucketEntry(useInit, initEntries, liveEntries, deadEntries);

    MergeCounters mc;
    BucketOutputIterator out(bucketManager.getTmpDir(), true, meta, mc, ctx,
                             doFsync);
    for (auto const& e : entries)
    {
        out.put(e);
    }

    if (countMergeEvents)
    {
        bucketManager.incrMergeCounters(mc);
    }

    // Make 2nd file in new sort order
    BucketMetadata metaV2;
    metaV2.ledgerVersion = protocolVersion;
    metaV2.ext.v(1);
    metaV2.ext.v1().flags = BucketMetadataFlags::BUCKET_METADATA_NEW_CMP_FLAG;

    BucketEntryIdCmpV2 cmp;
    std::sort(entries.begin(), entries.end(), cmp);
    BucketOutputIterator outV2(bucketManager.getTmpDir(), true, metaV2, mc, ctx,
                               doFsync);
    for (auto const& e : entries)
    {
        outV2.put(e);
    }

    return out.getBucket(bucketManager, /*mergeKey=*/nullptr, &outV2);
}

static void
countShadowedEntryType(MergeCounters& mc, BucketEntry const& e)
{
    switch (e.type())
    {
    case METAENTRY:
        ++mc.mMetaEntryShadowElisions;
        break;
    case INITENTRY:
        ++mc.mInitEntryShadowElisions;
        break;
    case LIVEENTRY:
        ++mc.mLiveEntryShadowElisions;
        break;
    case DEADENTRY:
        ++mc.mDeadEntryShadowElisions;
        break;
    }
}

void
Bucket::checkProtocolLegality(BucketEntry const& entry,
                              uint32_t protocolVersion)
{
    if (protocolVersion < FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY &&
        (entry.type() == INITENTRY || entry.type() == METAENTRY))
    {
        throw std::runtime_error(fmt::format(
            FMT_STRING("unsupported entry type {} in protocol {:d} bucket"),
            (entry.type() == INITENTRY ? "INIT" : "META"), protocolVersion));
    }
}

inline void
maybePut(BucketOutputIterator& out, BucketEntry const& entry,
         std::vector<BucketInputIterator>& shadowIterators,
         bool keepShadowedLifecycleEntries, MergeCounters& mc)
{
    // In ledgers before protocol 11, keepShadowedLifecycleEntries will be
    // `false` and we will drop all shadowed entries here.
    //
    // In ledgers at-or-after protocol 11, it will be `true` which means that we
    // only elide 'put'ing an entry if it is in LIVEENTRY state; we keep entries
    // in DEADENTRY and INITENTRY states, for two reasons:
    //
    //   - DEADENTRY is preserved to ensure that old live-or-init entries that
    //     were killed remain dead, are not brought back to life accidentally by
    //     having a newer shadow eliding their later DEADENTRY (tombstone). This
    //     is possible because newer shadowing entries may both refer to the
    //     same key as an older dead entry, and may occur as an INIT/DEAD pair
    //     that subsequently annihilate one another.
    //
    //     IOW we want to prevent the following scenario:
    //
    //       lev1:DEAD, lev2:INIT, lev3:DEAD, lev4:INIT
    //
    //     from turning into the following by shadowing:
    //
    //       lev1:DEAD, lev2:INIT, -elided-, lev4:INIT
    //
    //     and then the following by pairwise annihilation:
    //
    //       -annihilated-, -elided-, lev4:INIT
    //
    //   - INITENTRY is preserved to ensure that a DEADENTRY preserved by the
    //     previous rule does not itself shadow-out its own INITENTRY, but
    //     rather eventually ages and encounters (and is annihilated-by) that
    //     INITENTRY in an older level.  Thus preventing the accumulation of
    //     redundant tombstones.
    //
    // Note that this decision only controls whether to elide dead entries due
    // to _shadows_. There is a secondary elision of dead entries at the _oldest
    // level_ of the bucketlist that is accomplished through filtering at the
    // BucketOutputIterator level, and happens independent of ledger protocol
    // version.

    if (keepShadowedLifecycleEntries &&
        (entry.type() == INITENTRY || entry.type() == DEADENTRY))
    {
        // Never shadow-out entries in this case; no point scanning shadows.
        out.put(entry);
        return;
    }

    BucketEntryIdCmp cmp;
    for (auto& si : shadowIterators)
    {
        // Advance the shadowIterator while it's less than the candidate
        while (si && cmp(*si, entry))
        {
            ++mc.mShadowScanSteps;
            ++si;
        }
        // We have stepped si forward to the point that either si is exhausted,
        // or else *si >= entry; we now check the opposite direction to see if
        // we have equality.
        if (si && !cmp(entry, *si))
        {
            // If so, then entry is shadowed in at least one level.
            countShadowedEntryType(mc, entry);
            return;
        }
    }
    // Nothing shadowed.
    out.put(entry);
}

static void
countOldEntryType(MergeCounters& mc, BucketEntry const& e)
{
    switch (e.type())
    {
    case METAENTRY:
        ++mc.mOldMetaEntries;
        break;
    case INITENTRY:
        ++mc.mOldInitEntries;
        break;
    case LIVEENTRY:
        ++mc.mOldLiveEntries;
        break;
    case DEADENTRY:
        ++mc.mOldDeadEntries;
        break;
    }
}

static void
countNewEntryType(MergeCounters& mc, BucketEntry const& e)
{
    switch (e.type())
    {
    case METAENTRY:
        ++mc.mNewMetaEntries;
        break;
    case INITENTRY:
        ++mc.mNewInitEntries;
        break;
    case LIVEENTRY:
        ++mc.mNewLiveEntries;
        break;
    case DEADENTRY:
        ++mc.mNewDeadEntries;
        break;
    }
}

// The protocol used in a merge is the maximum of any of the protocols used in
// its input buckets, _including_ any of its shadows. We need to be strict about
// this for the same reason we change shadow algorithms along with merge
// algorithms: because once _any_ newer bucket levels have cut-over to merging
// with the new INITENTRY-supporting merge algorithm, there may be "INIT + DEAD
// => nothing" mutual annihilations occurring, which can "revive" the state of
// an entry on older levels. It's imperative then that older levels'
// lifecycle-event-pairing structure be preserved -- that the state-before INIT
// is in fact DEAD or nonexistent -- from the instant we begin using the new
// merge protocol: that the old lifecycle-event-eliding shadowing behaviour be
// disabled, and we switch to the more conservative shadowing behaviour that
// preserves lifecycle-events.
//
//     IOW we want to prevent the following scenario
//     (assuming lev1 and lev2 are on the new protocol, but 3 and 4
//      are on the old protocol):
//
//       lev1:DEAD, lev2:INIT, lev3:DEAD, lev4:LIVE
//
//     from turning into the following by shadowing
//     (using the old shadow algorithm on a lev3 merge):
//
//       lev1:DEAD, lev2:INIT, -elided-, lev4:LIVE
//
//     and then the following by pairwise annihilation
//     (using the new merge algorithm on new lev1 and lev2):
//
//       -annihilated-, -elided-, lev4:LIVE
//
// To prevent this, we cut over _all_ levels of the bucket list to the new merge
// and shadowing protocol simultaneously, the moment the first new-protocol
// bucket enters the youngest level. At least one new bucket is in every merge's
// shadows from then on in, so they all upgrade (and preserve lifecycle events).
static void
calculateMergeProtocolVersion(
    MergeCounters& mc, uint32_t maxProtocolVersion,
    BucketInputIterator const& oi, BucketInputIterator const& ni,
    std::vector<BucketInputIterator> const& shadowIterators,
    uint32& protocolVersion, bool& keepShadowedLifecycleEntries)
{
    protocolVersion = std::max(oi.getMetadata().ledgerVersion,
                               ni.getMetadata().ledgerVersion);

    // Starting with FIRST_PROTOCOL_SHADOWS_REMOVED,
    // protocol version is determined as a max of curr, snap, and any shadow of
    // version < FIRST_PROTOCOL_SHADOWS_REMOVED. This means that a bucket may
    // still perform an old style merge despite the presence of the new protocol
    // shadows.
    for (auto const& si : shadowIterators)
    {
        auto version = si.getMetadata().ledgerVersion;
        if (version < Bucket::FIRST_PROTOCOL_SHADOWS_REMOVED)
        {
            protocolVersion = std::max(version, protocolVersion);
        }
    }

    CLOG_TRACE(Bucket, "Bucket merge protocolVersion={}, maxProtocolVersion={}",
               protocolVersion, maxProtocolVersion);

    if (protocolVersion > maxProtocolVersion)
    {
        throw std::runtime_error(fmt::format(
            FMT_STRING(
                "bucket protocol version {:d} exceeds maxProtocolVersion {:d}"),
            protocolVersion, maxProtocolVersion));
    }

    // When merging buckets after protocol version 10 (i.e. version 11-or-after)
    // we switch shadowing-behaviour to a more conservative mode, in order to
    // support annihilation of INITENTRY and DEADENTRY pairs. See commentary
    // above in `maybePut`.
    keepShadowedLifecycleEntries = true;
    if (protocolVersion <
        Bucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY)
    {
        ++mc.mPreInitEntryProtocolMerges;
        keepShadowedLifecycleEntries = false;
    }
    else
    {
        ++mc.mPostInitEntryProtocolMerges;
    }

    if (protocolVersion < Bucket::FIRST_PROTOCOL_SHADOWS_REMOVED)
    {
        ++mc.mPreShadowRemovalProtocolMerges;
    }
    else
    {
        if (!shadowIterators.empty())
        {
            throw std::runtime_error("Shadows are not supported");
        }
        ++mc.mPostShadowRemovalProtocolMerges;
    }
}

// There are 4 "easy" cases for merging: exhausted iterators on either
// side, or entries that compare non-equal. In all these cases we just
// take the lesser (or existing) entry and advance only one iterator,
// not scrutinizing the entry type further.
static bool
mergeCasesWithDefaultAcceptance(
    BucketEntryIdCmp const& cmp, MergeCounters& mc, BucketInputIterator& oi,
    BucketInputIterator& ni, BucketOutputIterator& out,
    std::vector<BucketInputIterator>& shadowIterators, uint32_t protocolVersion,
    bool keepShadowedLifecycleEntries)
{
    if (!ni || (oi && ni && cmp(*oi, *ni)))
    {
        // Either of:
        //
        //   - Out of new entries.
        //   - Old entry has smaller key.
        //
        // In both cases: take old entry.
        ++mc.mOldEntriesDefaultAccepted;
        Bucket::checkProtocolLegality(*oi, protocolVersion);
        countOldEntryType(mc, *oi);
        maybePut(out, *oi, shadowIterators, keepShadowedLifecycleEntries, mc);
        ++oi;
        return true;
    }
    else if (!oi || (oi && ni && cmp(*ni, *oi)))
    {
        // Either of:
        //
        //   - Out of old entries.
        //   - New entry has smaller key.
        //
        // In both cases: take new entry.
        ++mc.mNewEntriesDefaultAccepted;
        Bucket::checkProtocolLegality(*ni, protocolVersion);
        countNewEntryType(mc, *ni);
        maybePut(out, *ni, shadowIterators, keepShadowedLifecycleEntries, mc);
        ++ni;
        return true;
    }
    return false;
}

// The remaining cases happen when keys are equal and we have to reason
// through the relationships of their bucket lifecycle states. Trickier.
static void
mergeCasesWithEqualKeys(MergeCounters& mc, BucketInputIterator& oi,
                        BucketInputIterator& ni, BucketOutputIterator& out,
                        std::vector<BucketInputIterator>& shadowIterators,
                        uint32_t protocolVersion,
                        bool keepShadowedLifecycleEntries)
{
    // Old and new are for the same key and neither is INIT, take the new
    // key. If either key is INIT, we have to make some adjustments:
    //
    //   old    |   new   |   result
    // ---------+---------+-----------
    //  INIT    |  INIT   |   error
    //  LIVE    |  INIT   |   error
    //  DEAD    |  INIT=x |   LIVE=x
    //  INIT=x  |  LIVE=y |   INIT=y
    //  INIT    |  DEAD   |   empty
    //
    //
    // What does this mean / why is it correct?
    //
    // Performing a merge between two same-key entries is about maintaining two
    // invariants:
    //
    //    1. From the perspective of a reader (eg. the database) the pre-merge
    //       pair of entries and post-merge single entry are indistinguishable,
    //       at least in terms that the reader/database cares about (liveness &
    //       value).  This is the most important invariant since it's what makes
    //       the database have the right values!
    //
    //    2. From the perspective of chronological _sequences_ of lifecycle
    //       transitions, if an entry is in INIT state then its (chronological)
    //       predecessor state is DEAD either by the next-oldest state being an
    //       _explicit_ DEAD tombstone, or by the INIT being the oldest state in
    //       the bucket list. This invariant allows us to assume that INIT
    //       followed by DEAD can be safely merged to empty (eliding the record)
    //       without revealing and reviving the key in some older non-DEAD state
    //       preceding the INIT.
    //
    // When merging a pair of non-INIT entries and taking the 'new' value,
    // invariant #1 is easy to see as preserved (an LSM tree is defined as
    // returning the newest value for an entry, so preserving the newest of any
    // pair is correct), and by assumption neither entry is INIT-state so
    // invariant #2 isn't relevant / is unaffected.
    //
    // When merging a pair with an INIT, we can go case-by-case through the
    // table above and see that both invariants are preserved:
    //
    //   - INIT,INIT and LIVE,INIT violate invariant #2, so by assumption should
    //     never be occurring.
    //
    //   - DEAD,INIT=x are indistinguishable from LIVE=x from the perspective of
    //     the reader, satisfying invariant #1. And since LIVE=x is not
    //     INIT-state anymore invariant #2 is trivially preserved (does not
    //     apply).
    //
    //   - INIT=x,LIVE=y is indistinguishable from INIT=y from the perspective
    //     of the reader, satisfying invariant #1.  And assuming invariant #2
    //     holds for INIT=x,LIVE=y, then it holds for INIT=y.
    //
    //   - INIT,DEAD is indistinguishable from absence-of-an-entry from the
    //     perspective of a reader, maintaining invariant #1, _if_ invariant #2
    //     also holds (the predecessor state _before_ INIT was
    //     absent-or-DEAD). And invariant #2 holds trivially _locally_ for this
    //     merge because there is no resulting state (i.e. it's not in
    //     INIT-state); and it holds slightly-less-trivially non-locally,
    //     because even if there is a subsequent (newer) INIT entry, the
    //     invariant is maintained for that newer entry too (it is still
    //     preceded by a DEAD state).

    BucketEntry const& oldEntry = *oi;
    BucketEntry const& newEntry = *ni;
    Bucket::checkProtocolLegality(oldEntry, protocolVersion);
    Bucket::checkProtocolLegality(newEntry, protocolVersion);
    countOldEntryType(mc, oldEntry);
    countNewEntryType(mc, newEntry);

    if (newEntry.type() == INITENTRY)
    {
        // The only legal new-is-INIT case is merging a delete+create to an
        // update.
        if (oldEntry.type() != DEADENTRY)
        {
            throw std::runtime_error(
                "Malformed bucket: old non-DEAD + new INIT.");
        }
        BucketEntry newLive;
        newLive.type(LIVEENTRY);
        newLive.liveEntry() = newEntry.liveEntry();
        ++mc.mNewInitEntriesMergedWithOldDead;
        maybePut(out, newLive, shadowIterators, keepShadowedLifecycleEntries,
                 mc);
    }
    else if (oldEntry.type() == INITENTRY)
    {
        // If we get here, new is not INIT; may be LIVE or DEAD.
        if (newEntry.type() == LIVEENTRY)
        {
            // Merge a create+update to a fresher create.
            BucketEntry newInit;
            newInit.type(INITENTRY);
            newInit.liveEntry() = newEntry.liveEntry();
            ++mc.mOldInitEntriesMergedWithNewLive;
            maybePut(out, newInit, shadowIterators,
                     keepShadowedLifecycleEntries, mc);
        }
        else
        {
            // Merge a create+delete to nothingness.
            if (newEntry.type() != DEADENTRY)
            {
                throw std::runtime_error(
                    "Malformed bucket: old INIT + new non-DEAD.");
            }
            ++mc.mOldInitEntriesMergedWithNewDead;
        }
    }
    else
    {
        // Neither is in INIT state, take the newer one.
        ++mc.mNewEntriesMergedWithOldNeitherInit;
        maybePut(out, newEntry, shadowIterators, keepShadowedLifecycleEntries,
                 mc);
    }
    ++oi;
    ++ni;
}

std::shared_ptr<Bucket>
Bucket::merge(BucketManager& bucketManager, uint32_t maxProtocolVersion,
              std::shared_ptr<Bucket> const& oldBucket,
              std::shared_ptr<Bucket> const& newBucket,
              std::vector<std::shared_ptr<Bucket>> const& shadows,
              bool keepDeadEntries, bool countMergeEvents,
              asio::io_context& ctx, bool doFsync)
{
    ZoneScoped;
    // This is the key operation in the scheme: merging two (read-only)
    // buckets together into a new 3rd bucket, while calculating its hash,
    // in a single pass.

    releaseAssert(oldBucket);
    releaseAssert(newBucket);

    MergeCounters mc;
    BucketInputIterator oi(oldBucket, oldBucket->getFilename());
    BucketInputIterator ni(newBucket, newBucket->getFilename());
    BucketInputIterator oV2i(oldBucket, oldBucket->getV2Filename());
    BucketInputIterator nV2i(newBucket, newBucket->getV2Filename());
    std::vector<BucketInputIterator> shadowIterators(shadows.begin(),
                                                     shadows.end());

    uint32_t protocolVersion;
    bool keepShadowedLifecycleEntries;
    calculateMergeProtocolVersion(mc, maxProtocolVersion, oi, ni,
                                  shadowIterators, protocolVersion,
                                  keepShadowedLifecycleEntries);

    auto timer = bucketManager.getMergeTimer().TimeScope();
    BucketMetadata meta;
    meta.ledgerVersion = protocolVersion;
    BucketOutputIterator out(bucketManager.getTmpDir(), keepDeadEntries, meta,
                             mc, ctx, doFsync);

    BucketEntryIdCmp cmp;
    size_t iter = 0;

    while (oi || ni)
    {
        // Check if the merge should be stopped every few entries
        if (++iter >= 1000)
        {
            iter = 0;
            if (bucketManager.isShutdown())
            {
                // Stop merging, as BucketManager is now shutdown
                // This is safe as temp file has not been adopted yet,
                // so it will be removed with the tmp dir
                throw std::runtime_error(
                    "Incomplete bucket merge due to BucketManager shutdown");
            }
        }

        if (!mergeCasesWithDefaultAcceptance(cmp, mc, oi, ni, out,
                                             shadowIterators, protocolVersion,
                                             keepShadowedLifecycleEntries))
        {
            mergeCasesWithEqualKeys(mc, oi, ni, out, shadowIterators,
                                    protocolVersion,
                                    keepShadowedLifecycleEntries);
        }
    }

    BucketMetadata metaV2;
    MergeCounters mc2;
    metaV2.ledgerVersion = protocolVersion;
    metaV2.ext.v(1);
    metaV2.ext.v1().flags = BucketMetadataFlags::BUCKET_METADATA_NEW_CMP_FLAG;
    BucketOutputIterator outV2(bucketManager.getTmpDir(), keepDeadEntries,
                               metaV2, mc2, ctx, doFsync);

    BucketEntryIdCmpV2 cmp2;
    while (oV2i || nV2i)
    {
        // Check if the merge should be stopped every few entries
        if (++iter >= 1000)
        {
            iter = 0;
            if (bucketManager.isShutdown())
            {
                // Stop merging, as BucketManager is now shutdown
                // This is safe as temp file has not been adopted yet,
                // so it will be removed with the tmp dir
                throw std::runtime_error(
                    "Incomplete bucket merge due to BucketManager shutdown");
            }
        }

        if (!mergeCasesWithDefaultAcceptance(cmp2, mc2, oV2i, nV2i, outV2,
                                             shadowIterators, protocolVersion,
                                             keepShadowedLifecycleEntries))
        {
            mergeCasesWithEqualKeys(mc2, oV2i, nV2i, outV2, shadowIterators,
                                    protocolVersion,
                                    keepShadowedLifecycleEntries);
        }
    }

    if (countMergeEvents)
    {
        bucketManager.incrMergeCounters(mc);
    }

    MergeKey mk{keepDeadEntries, oldBucket, newBucket, shadows};

    // Clear and invalidate old indexes
    oldBucket->mIndex = nullptr;
    newBucket->mIndex = nullptr;
    return out.getBucket(bucketManager, &mk, &outV2);
}

uint32_t
Bucket::getBucketVersion(std::shared_ptr<Bucket const> bucket)
{
    releaseAssert(bucket);
    BucketInputIterator it(bucket);
    return it.getMetadata().ledgerVersion;
}
}
